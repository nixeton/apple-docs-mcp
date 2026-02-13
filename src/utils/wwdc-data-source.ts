/**
 * WWDC Data Source - Loads data from bundled JSON files
 *
 * This module provides functions to load WWDC video data from
 * JSON files that are bundled with the npm package.
 */

import { promises as fs } from 'fs';
import path from 'path';
import { logger } from './logger.js';
import { wwdcDataCache } from './cache.js';
import { WWDC_CONFIG } from './constants.js';
import { getWWDCDataDirectory } from './wwdc-data-source-path.js';
import type { WWDCVideo, GlobalMetadata, TopicIndex, YearIndex } from '../types/wwdc.js';

// Get the data directory from the separate module
const WWDC_DATA_DIR = getWWDCDataDirectory();

/**
 * Validate that a resolved path is contained within the data directory.
 * Prevents path traversal attacks (e.g., "../../etc/passwd").
 */
function assertPathWithinDataDir(resolvedPath: string): void {
  const normalizedBase = path.resolve(WWDC_DATA_DIR) + path.sep;
  const normalizedTarget = path.resolve(resolvedPath);
  if (!normalizedTarget.startsWith(normalizedBase) && normalizedTarget !== path.resolve(WWDC_DATA_DIR)) {
    throw new Error('Invalid data path: access denied');
  }
}

/**
 * Read file from bundled data directory
 */
async function readBundledFile(filePath: string): Promise<string> {
  const fullPath = path.join(WWDC_DATA_DIR, filePath);

  // Prevent path traversal — ensure resolved path stays within data directory
  assertPathWithinDataDir(fullPath);

  try {
    const content = await fs.readFile(fullPath, 'utf-8');
    logger.debug(`Loaded bundled data: ${filePath}`);
    return content;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error(`Failed to read bundled data: ${filePath}`, error);
    throw new Error(`Failed to load WWDC data from ${filePath}: ${errorMessage}`);
  }
}

/**
 * Fetch data with caching support
 */
async function fetchData(filePath: string): Promise<string> {
  const cacheKey = `wwdc:${filePath}`;

  // Check cache first
  const cached = wwdcDataCache.get<string>(cacheKey);
  if (cached) {
    logger.debug(`Cache hit: ${filePath}`);
    return cached;
  }

  // Read from bundled data
  const data = await readBundledFile(filePath);

  // Cache the data
  wwdcDataCache.set(cacheKey, data, WWDC_CONFIG.CACHE_TTL);

  return data;
}

/**
 * Load global metadata (index.json)
 */
export async function loadGlobalMetadata(): Promise<GlobalMetadata> {
  try {
    const data = await fetchData('index.json');
    return JSON.parse(data);
  } catch (error) {
    logger.error('Failed to load global metadata', error);
    throw new Error('Failed to load WWDC metadata. Please ensure the package is properly installed.');
  }
}

/**
 * Validate year format (4 digits only)
 */
function validateYear(year: string): void {
  if (!/^\d{4}$/.test(year)) {
    throw new Error(`Invalid year format: ${year}`);
  }
}

/**
 * Validate video ID format (digits only)
 */
function validateVideoId(videoId: string): void {
  if (!/^\d+$/.test(videoId)) {
    throw new Error(`Invalid video ID format: ${videoId}`);
  }
}

/**
 * Validate topic ID format (lowercase alphanumeric and hyphens only)
 */
function validateTopicId(topicId: string): void {
  if (!/^[a-zA-Z0-9-]+$/.test(topicId)) {
    throw new Error(`Invalid topic ID format: ${topicId}`);
  }
}

/**
 * Load topic index
 */
export async function loadTopicIndex(topicId: string): Promise<TopicIndex> {
  validateTopicId(topicId);
  try {
    const data = await fetchData(`by-topic/${topicId}/index.json`);
    return JSON.parse(data);
  } catch (error) {
    logger.error(`Failed to load topic index: ${topicId}`, error);
    throw new Error(`Topic not found: ${topicId}`);
  }
}

/**
 * Load year index
 */
export async function loadYearIndex(year: string): Promise<YearIndex> {
  validateYear(year);
  try {
    const data = await fetchData(`by-year/${year}/index.json`);
    return JSON.parse(data);
  } catch (error) {
    logger.error(`Failed to load year index: ${year}`, error);
    throw new Error(`Year not found: ${year}`);
  }
}

/**
 * Load individual video data
 */
export async function loadVideoData(year: string, videoId: string): Promise<WWDCVideo> {
  validateYear(year);
  validateVideoId(videoId);
  try {
    const data = await fetchData(`videos/${year}-${videoId}.json`);
    return JSON.parse(data);
  } catch (error) {
    logger.error(`Failed to load video: ${year}-${videoId}`, error);
    throw new Error(`Video not found: ${year}-${videoId}`);
  }
}

/**
 * Load all videos list
 */
export async function loadAllVideos(): Promise<WWDCVideo[]> {
  try {
    const data = await fetchData('all-videos.json');
    return JSON.parse(data);
  } catch (error) {
    logger.error('Failed to load all videos', error);
    throw new Error('Failed to load WWDC video list');
  }
}

/**
 * Clear the WWDC data cache
 */
export function clearDataCache(): void {
  wwdcDataCache.clear();
  logger.info('WWDC data cache cleared');
}

/**
 * Check if WWDC data is available
 */
export async function isDataAvailable(): Promise<boolean> {
  try {
    await fs.access(WWDC_DATA_DIR);
    await fs.access(path.join(WWDC_DATA_DIR, 'index.json'));
    return true;
  } catch {
    return false;
  }
}