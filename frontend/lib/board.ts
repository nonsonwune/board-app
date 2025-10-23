export function formatBoardName(boardId: string, displayName?: string | null): string {
  if (displayName && displayName.trim()) {
    return displayName.trim();
  }
  const cleaned = boardId.replace(/[-_]+/g, ' ').trim();
  if (!cleaned) {
    return boardId;
  }
  return cleaned
    .split(' ')
    .filter(Boolean)
    .map(word => word[0]?.toUpperCase() + word.slice(1))
    .join(' ');
}
