"use client";

import { useState, useMemo } from "react";
import { Calendar, Play, Pause } from "lucide-react";
import { Slider } from "@/components/ui/slider";
import { Button } from "@/components/ui/button";
import type { AsnGroup } from "@/lib/network-types";

interface TimelineSliderProps {
  groups: AsnGroup[];
  onDateRangeChange: (startDate: Date | null, endDate: Date | null) => void;
}

export function TimelineSlider({ groups, onDateRangeChange }: TimelineSliderProps) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [sliderValue, setSliderValue] = useState<[number, number]>([0, 100]);

  // Extract date range from all records
  const { minDate, maxDate, dateRange } = useMemo(() => {
    let min = Infinity;
    let max = -Infinity;

    for (const group of groups) {
      for (const record of group.records) {
        if (record.first_seen) {
          const d = new Date(record.first_seen).getTime();
          if (!isNaN(d)) {
            min = Math.min(min, d);
            max = Math.max(max, d);
          }
        }
        if (record.last_seen) {
          const d = new Date(record.last_seen).getTime();
          if (!isNaN(d)) {
            max = Math.max(max, d);
          }
        }
      }
    }

    if (min === Infinity) min = Date.now() - 365 * 24 * 60 * 60 * 1000;
    if (max === -Infinity) max = Date.now();

    return {
      minDate: new Date(min),
      maxDate: new Date(max),
      dateRange: max - min,
    };
  }, [groups]);

  // Convert slider percentage to dates
  const selectedStartDate = useMemo(() => {
    return new Date(minDate.getTime() + (dateRange * sliderValue[0]) / 100);
  }, [minDate, dateRange, sliderValue]);

  const selectedEndDate = useMemo(() => {
    return new Date(minDate.getTime() + (dateRange * sliderValue[1]) / 100);
  }, [minDate, dateRange, sliderValue]);

  // Count records in selected range
  const recordsInRange = useMemo(() => {
    let count = 0;
    for (const group of groups) {
      for (const record of group.records) {
        const firstSeen = record.first_seen ? new Date(record.first_seen).getTime() : 0;
        const lastSeen = record.last_seen ? new Date(record.last_seen).getTime() : Date.now();
        if (lastSeen >= selectedStartDate.getTime() && firstSeen <= selectedEndDate.getTime()) {
          count++;
        }
      }
    }
    return count;
  }, [groups, selectedStartDate, selectedEndDate]);

  const totalRecords = useMemo(() => {
    return groups.reduce((sum, g) => sum + g.records.length, 0);
  }, [groups]);

  const handleSliderChange = (value: number[]) => {
    setSliderValue([value[0], value[1]]);
    onDateRangeChange(
      new Date(minDate.getTime() + (dateRange * value[0]) / 100),
      new Date(minDate.getTime() + (dateRange * value[1]) / 100)
    );
  };

  const handleReset = () => {
    setSliderValue([0, 100]);
    onDateRangeChange(null, null);
  };

  const formatDate = (date: Date) => {
    return date.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  if (groups.length === 0) return null;

  return (
    <div className="flex flex-col gap-3 rounded-lg border border-border bg-card p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Calendar className="h-4 w-4 text-primary" />
          <h3 className="text-sm font-semibold text-foreground">Timeline</h3>
        </div>
        <span className="text-xs text-muted-foreground font-mono">
          {recordsInRange.toLocaleString()} / {totalRecords.toLocaleString()} records
        </span>
      </div>

      {/* Date range display */}
      <div className="flex items-center justify-between text-xs">
        <span className="font-mono text-primary">{formatDate(selectedStartDate)}</span>
        <span className="text-muted-foreground">to</span>
        <span className="font-mono text-primary">{formatDate(selectedEndDate)}</span>
      </div>

      {/* Slider */}
      <div className="px-1">
        <Slider
          value={sliderValue}
          onValueChange={handleSliderChange}
          min={0}
          max={100}
          step={1}
          className="w-full"
        />
      </div>

      {/* Min/max labels */}
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>{formatDate(minDate)}</span>
        <span>{formatDate(maxDate)}</span>
      </div>

      {/* Controls */}
      <div className="flex gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => setIsPlaying(!isPlaying)}
          disabled
          className="flex-1 gap-2 text-xs"
        >
          {isPlaying ? <Pause className="h-3 w-3" /> : <Play className="h-3 w-3" />}
          {isPlaying ? "Pause" : "Animate"}
        </Button>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={handleReset}
          className="text-xs"
        >
          Reset
        </Button>
      </div>
    </div>
  );
}
