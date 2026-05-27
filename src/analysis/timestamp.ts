const MONTHS: Record<string, string> = {
  Jan: "01",
  Feb: "02",
  Mar: "03",
  Apr: "04",
  May: "05",
  Jun: "06",
  Jul: "07",
  Aug: "08",
  Sep: "09",
  Oct: "10",
  Nov: "11",
  Dec: "12"
};

export function parseAccessLogTimestamp(timestamp: string): Date | null {
  const match =
    /^(?<day>\d{2})\/(?<month>[A-Za-z]{3})\/(?<year>\d{4}):(?<time>\d{2}:\d{2}:\d{2}) (?<offset>[+-]\d{4})$/.exec(
      timestamp
    );

  if (!match?.groups) {
    const fallback = new Date(timestamp);
    return Number.isNaN(fallback.getTime()) ? null : fallback;
  }

  const month = monthNumber(match.groups.month);

  if (month === null) {
    return null;
  }

  const offset = match.groups.offset;
  const iso = `${match.groups.year}-${month}-${match.groups.day}T${match.groups.time}${offset.slice(0, 3)}:${offset.slice(3)}`;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function accessLogTimestampToEpochSeconds(timestamp: string): number | null {
  const date = parseAccessLogTimestamp(timestamp);
  return date ? Math.floor(date.getTime() / 1000) : null;
}

function monthNumber(month: string): string | null {
  return MONTHS[month] ?? null;
}
