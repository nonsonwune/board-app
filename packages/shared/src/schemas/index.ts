import { z } from 'zod';

export const PostImageDraftSchema = z.object({
  id: z.string().optional(),
  name: z.string(),
  type: z.string(),
  size: z.number(),
  width: z.number().optional(),
  height: z.number().optional(),
  checksum: z.string().optional(),
});

export const CreatePostSchema = z.object({
  body: z.string().min(1, 'Body is required'),
  author: z.string().optional(),
  userId: z.string().optional(),
  images: z.array(PostImageDraftSchema).optional(),
});

export const CreateReplySchema = z.object({
  body: z.string().min(1, 'Body is required'),
  userId: z.string().optional(),
  author: z.string().optional(),
});

export const ReactionActionSchema = z.enum(['like', 'dislike', 'remove']);

export const UpdateReactionSchema = z.object({
  userId: z.string(),
  action: ReactionActionSchema,
});

export const RegisterIdentitySchema = z.object({
  pseudonym: z.string().min(3).max(20),
});

export const UpsertAliasSchema = z.object({
  userId: z.string(),
  alias: z.string().min(3).max(24),
});
