/**
 * Zod schemas for WWDC tools
 */

import { z } from 'zod';

// Reusable safe-input patterns to prevent path traversal
const safeYearSchema = z.string().regex(/^\d{4}$/, 'Year must be exactly 4 digits (e.g., "2024")');
const safeVideoIdSchema = z.string().regex(/^\d+$/, 'Video ID must contain only digits');
const safeTopicIdSchema = z.string().regex(/^[a-zA-Z0-9-]+$/, 'Topic ID must contain only alphanumeric characters and hyphens');

/**
 * Schema for list_wwdc_videos
 */
export const listWWDCVideosSchema = z.object({
  year: safeYearSchema.optional().describe('Filter by WWDC year'),
  topic: z.string().max(200).optional().describe('Filter by topic keyword'),
  hasCode: z.boolean().optional().describe('Filter by code availability'),
  limit: z.number().min(1).max(200).default(50).describe('Maximum number of videos'),
});

/**
 * Schema for search_wwdc_content
 */
export const searchWWDCContentSchema = z.object({
  query: z.string().min(1).max(500).describe('Search query'),
  searchIn: z.enum(['transcript', 'code', 'both']).default('both').describe('Where to search'),
  year: safeYearSchema.optional().describe('Filter by WWDC year'),
  language: z.string().max(50).optional().describe('Filter code by language'),
  limit: z.number().min(1).max(100).default(20).describe('Maximum number of results'),
});

/**
 * Schema for get_wwdc_video
 */
export const getWWDCVideoSchema = z.object({
  year: safeYearSchema.describe('WWDC year'),
  videoId: safeVideoIdSchema.describe('Video ID'),
  includeTranscript: z.boolean().default(true).describe('Include transcript'),
  includeCode: z.boolean().default(true).describe('Include code examples'),
});

/**
 * Schema for get_wwdc_code_examples
 */
export const getWWDCCodeExamplesSchema = z.object({
  framework: z.string().max(200).optional().describe('Filter by framework'),
  topic: z.string().max(200).optional().describe('Filter by topic'),
  year: safeYearSchema.optional().describe('Filter by WWDC year'),
  language: z.string().max(50).optional().describe('Filter by programming language'),
  limit: z.number().min(1).max(100).default(30).describe('Maximum number of examples'),
});

/**
 * Schema for browse_wwdc_topics
 */
export const browseWWDCTopicsSchema = z.object({
  topicId: safeTopicIdSchema.optional().describe('Specific topic ID to browse'),
  includeVideos: z.boolean().default(true).describe('Include video list'),
  year: safeYearSchema.optional().describe('Filter videos by year'),
  limit: z.number().min(1).max(100).default(20).describe('Maximum number of videos per topic'),
});

/**
 * Schema for find_related_wwdc_videos
 */
export const findRelatedWWDCVideosSchema = z.object({
  videoId: safeVideoIdSchema.describe('Video ID to find related videos for'),
  year: safeYearSchema.describe('Year of the source video'),
  includeExplicitRelated: z.boolean().default(true).describe('Include explicitly related videos'),
  includeTopicRelated: z.boolean().default(true).describe('Include videos from same topics'),
  includeYearRelated: z.boolean().default(false).describe('Include videos from same year'),
  limit: z.number().min(1).max(50).default(15).describe('Maximum number of related videos'),
});

/**
 * Schema for list_wwdc_years
 */
export const listWWDCYearsSchema = z.object({});