// whisperbox contract — question types + answer validation (JS reference; whisperbox_core
// mirrors it in whisperbox_engine.hpp, pinned by test/fixtures/answer-validation.json).
//
// Answer values by question type (questionId -> value):
//   text, textarea, email, url   string            (email / url: format-checked)
//   radioButtons, dropdown       option index      | {other: "text"} when q.allowOther
//   checkbox                     [index...]        (+ one {other: "text"} when q.allowOther)
//   boolean                      true | false
//   scale                        integer in [q.min ?? 1, q.max ?? 5]   (q.style "numbers"|"stars")
//   number                       finite number in [q.min, q.max] when set
//   date                         "YYYY-MM-DD"      time  "HH:MM" (24 h)
//   section                      no answer (a page break; q.text = section title)
// Unknown types accept a string (forward compatibility).
export const QUESTION_TYPES = Object.freeze(["text", "textarea", "radioButtons", "dropdown", "checkbox", "boolean",
  "scale", "number", "date", "time", "email", "url", "section"]);

const isOther = (v) => v !== null && typeof v === "object" && !Array.isArray(v) && "other" in v;
export function emptyAnswer(v) {
  if (v === null || v === undefined) return true;
  if (typeof v === "string") return v.trim() === "";
  if (Array.isArray(v)) return v.length === 0;
  if (isOther(v)) return String(v.other ?? "").trim() === "";
  return false;
}
const isInt = (x) => typeof x === "number" && Number.isInteger(x);
const num = (x, d) => (typeof x === "number" && Number.isFinite(x) ? x : d);
function validDate(s) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s); if (!m) return false;
  const y = +m[1], mo = +m[2], d = +m[3];
  if (mo < 1 || mo > 12 || d < 1) return false;
  const days = [31, (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1];
  return d <= days;
}

/** "" when ok, else a short reason. Empty answers are only checked for `required`. */
export function validateAnswer(q, v) {
  const t = String(q?.type ?? "text");
  if (t === "section") return "";
  if (emptyAnswer(v)) return q?.required ? "required" : "";
  const n = Array.isArray(q?.options) ? q.options.length : 0;
  const otherOk = (x) => !!q?.allowOther && isOther(x) && typeof x.other === "string" && x.other.trim() !== "";
  switch (t) {
    case "text": case "textarea":
      return typeof v === "string" ? "" : "must be text";
    case "email":
      return typeof v === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim()) ? "" : "not an email address";
    case "url":
      return typeof v === "string" && /^https?:\/\/\S+\.\S+$/i.test(v.trim()) ? "" : "not a link (https://...)";
    case "radioButtons": case "dropdown":
      return (isInt(v) && v >= 0 && v < n) || otherOk(v) ? "" : "not one of the options";
    case "checkbox": {
      if (!Array.isArray(v)) return "not a list of options";
      const seen = new Set(); let others = 0;
      for (const x of v) {
        if (otherOk(x)) { others++; continue; }
        if (!isInt(x) || x < 0 || x >= n || seen.has(x)) return "not one of the options";
        seen.add(x);
      }
      return others > 1 ? "only one 'other' answer" : "";
    }
    case "boolean":
      return typeof v === "boolean" ? "" : "must be yes or no";
    case "scale": {
      const lo = num(q.min, 1), hi = num(q.max, 5);
      return isInt(v) && v >= lo && v <= hi ? "" : `must be ${lo}-${hi}`;
    }
    case "number":
      if (typeof v !== "number" || !Number.isFinite(v)) return "must be a number";
      if (typeof q.min === "number" && v < q.min) return `at least ${q.min}`;
      if (typeof q.max === "number" && v > q.max) return `at most ${q.max}`;
      return "";
    case "date":
      return typeof v === "string" && validDate(v) ? "" : "not a date (YYYY-MM-DD)";
    case "time":
      return typeof v === "string" && /^([01]\d|2[0-3]):[0-5]\d$/.test(v) ? "" : "not a time (HH:MM)";
    default:
      return typeof v === "string" ? "" : "must be text";
  }
}
/** First problem in an answer set: {questionId, error} or null. */
export function validateAnswers(questions, answers) {
  const byQ = new Map((answers || []).map((a) => [a?.questionId, a?.value]));
  for (const q of questions || []) {
    const e = validateAnswer(q, byQ.get(q.id));
    if (e) return { questionId: q.id, error: (q.text || q.id) + ": " + e };
  }
  return null;
}
