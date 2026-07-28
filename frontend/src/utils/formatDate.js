export function getFormattedUTCTime(date = new Date()) {
  return date.toUTCString().replace("GMT", "UTC");
}
