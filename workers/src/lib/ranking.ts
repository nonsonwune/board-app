// Ranking and scoring algorithms for posts

const TIME_DECAY_HALF_LIFE_MS = 24 * 60 * 60 * 1000;
const VELOCITY_DECAY_MS = 90 * 60 * 1000;
const VELOCITY_RATE_SATURATION = 5; // reactions per minute for full velocity credit
const WILSON_Z = 1.96; // 95% confidence interval

export function calculateWilsonScore(likeCount: number, dislikeCount: number): number {
    const total = likeCount + dislikeCount;
    if (total === 0) {
        return 0;
    }
    const z = WILSON_Z;
    const phat = likeCount / total;
    const denominator = 1 + (z ** 2) / total;
    const centreAdjustment = phat + (z ** 2) / (2 * total);
    const adjustedStd = z * Math.sqrt((phat * (1 - phat) + (z ** 2) / (4 * total)) / total);
    const score = (centreAdjustment - adjustedStd) / denominator;
    return Number.isFinite(score) ? Math.max(0, score) : 0;
}

export function calculateTimeDecay(createdAt: number, now: number): number {
    const ageMs = Math.max(0, now - createdAt);
    if (ageMs === 0) {
        return 1;
    }
    const decay = Math.exp((-Math.log(2) * ageMs) / TIME_DECAY_HALF_LIFE_MS);
    return Number.isFinite(decay) ? decay : 0;
}

export function calculateVelocityBoost(reactionCount: number, createdAt: number, now: number): number {
    if (reactionCount <= 0) {
        return 0;
    }
    const ageMs = Math.max(1000, now - createdAt);
    const ageMinutes = ageMs / 60_000;
    const reactionsPerMinute = reactionCount / Math.max(ageMinutes, 1 / 60);
    const normalizedRate = Math.min(reactionsPerMinute / VELOCITY_RATE_SATURATION, 1);
    const freshness = Math.exp(-ageMs / VELOCITY_DECAY_MS);
    const boost = normalizedRate * freshness;
    return Number.isFinite(boost) ? boost : 0;
}

export function calculateHotRank(
    likeCount: number,
    dislikeCount: number,
    reactionCount: number,
    createdAt: number,
    now: number
): number {
    const wilson = calculateWilsonScore(likeCount, dislikeCount);
    const timeDecay = calculateTimeDecay(createdAt, now);
    const velocityBonus = calculateVelocityBoost(reactionCount, createdAt, now);
    const authorBonus = 1; // placeholder until leaderboard integration
    const base = 0.5 * timeDecay + 0.45 * wilson + 0.05 * authorBonus;
    return base + velocityBonus * 0.15;
}
