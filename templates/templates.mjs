// Form templates for event organisers (Frequencies and anyone else): plain form definitions
// (SPEC §4.3/4.4) that createForm accepts as they are, on the phone (client.createForm) and on
// the desktop (whisperbox_core.createForm(JSON.stringify(def))). Same definitions on both.
//
//   import { template, TEMPLATES } from ".../templates/templates.mjs";
//   const def = template("guestlist", { title: "Guest list - Fri 14 Nov", expiresAt });
//
// Question ids are stable (q1, q2, ...): code that reads answers can rely on them.

const q = (id, type, text, extra = {}) => ({ id, type, text, required: false, ...extra });

export const TEMPLATES = {
  booking: {
    title: "Booking request",
    description: "Tell us about your act. Only the promoter can read this.",
    questions: [
      q("q1", "text", "Artist / act name", { required: true }),
      q("q2", "email", "Contact email", { required: true }),
      q("q3", "text", "Phone or other contact"),
      q("q4", "date", "Preferred date", { required: true }),
      q("q5", "date", "Alternative date"),
      q("q6", "number", "Fee (EUR)", { min: 0 }),
      q("q7", "dropdown", "Set type", { options: ["DJ set", "Live", "Hybrid"], allowOther: true }),
      q("q8", "number", "Set length (minutes)", { min: 15, max: 600 }),
      q("q9", "textarea", "Tech rider / equipment needs"),
      q("q10", "url", "Rider or press kit link"),
      q("q11", "url", "Music link (SoundCloud, Bandcamp, ...)"),
      q("q12", "textarea", "Anything else"),
    ],
  },
  crew: {
    title: "Crew sign-up",
    description: "Sign up to help. Only the organisers can read this.",
    questions: [
      q("q1", "text", "Name", { required: true }),
      q("q2", "text", "Contact (phone / Signal / email)", { required: true }),
      q("q3", "checkbox", "Roles you can do", { required: true, options: ["Door", "Bar", "Sound", "Lights", "Stage", "Setup / teardown", "Runner", "Awareness"], allowOther: true }),
      q("q4", "textarea", "Experience"),
      q("q5", "boolean", "Can you do setup before doors?"),
      q("q6", "textarea", "Anything we should know (accessibility, times you can't do)"),
    ],
  },
  guestlist: {
    title: "Guest list",
    description: "Request a place on the guest list. Your confirmation code is your ticket at the door.",
    maxResponses: 100,
    questions: [
      q("q1", "text", "Name on the list", { required: true }),
      q("q2", "number", "Plus ones", { min: 0, max: 3 }),
      q("q3", "text", "Who invited you?"),
    ],
  },
  feedback: {
    title: "How was the night?",
    description: "Anonymous: nobody can tell who answered.",
    anonymous: true,
    questions: [
      q("q1", "scale", "Overall", { required: true, min: 1, max: 5, style: "stars" }),
      q("q2", "scale", "Sound", { min: 1, max: 5, style: "stars" }),
      q("q3", "scale", "Did you feel safe?", { min: 1, max: 5, minLabel: "No", maxLabel: "Completely" }),
      q("q4", "textarea", "What should we change?"),
      q("q5", "textarea", "Anything else"),
    ],
  },
};

/** A fresh copy of a template, with fields overridden (title, description, expiresAt,
 *  maxResponses, ...). Unknown names throw, so a typo doesn't publish an empty form. */
export function template(name, overrides = {}) {
  const t = TEMPLATES[name];
  if (!t) throw new Error("unknown template: " + name + " (have: " + Object.keys(TEMPLATES).join(", ") + ")");
  return { ...JSON.parse(JSON.stringify(t)), ...overrides };
}
