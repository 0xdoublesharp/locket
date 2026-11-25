import { describe, expect, it } from 'vitest';
import { formatDuration } from './formatTime';

describe('formatDuration', () => {
  it('formats exact normalized hours, minutes, and seconds without rounding overflow', () => {
    expect(formatDuration(0)).toBe('0 sec');
    expect(formatDuration(45)).toBe('45 sec');
    expect(formatDuration(60)).toBe('1 min');
    expect(formatDuration(119)).toBe('1 min 59 sec');
    expect(formatDuration(900)).toBe('15 min');
    expect(formatDuration(3600)).toBe('1 hr');
    expect(formatDuration(3601)).toBe('1 hr 1 sec');
    expect(formatDuration(7199)).toBe('1 hr 59 min 59 sec');
  });
});
