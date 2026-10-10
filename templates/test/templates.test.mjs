// Every template is a form the client publishes as is, and its questions validate answers.
import { test } from "node:test";
import assert from "node:assert/strict";
import { TEMPLATES, template } from "../templates.mjs";
import { WhisperboxClient } from "../../client/src/client.mjs";
import { validateAnswers } from "../../contract/src/answers.mjs";

const mem = () => { const m = new Map(); return { get: async (k) => m.get(k) ?? null, set: async (k, v) => { m.set(k, v); } }; };

test("each template publishes and accepts a minimal answer", async () => {
  const c = new WhisperboxClient({ store: mem(), send: async () => {} });
  await c.init();
  for (const name of Object.keys(TEMPLATES)) {
    const r = c.createForm(template(name, { title: name + " test" }));
    assert.ok(r.ok, name + ": " + JSON.stringify(r));
    const f = c.snapshot().state.forms[r.formId];
    assert.equal(f.title, name + " test");
    assert.deepEqual(f.questions.map((x) => x.id), TEMPLATES[name].questions.map((x) => x.id), name + ": question ids kept");
    const sample = { text: "x", email: "a@b.cz", date: "2026-11-14", number: 1, dropdown: 0, checkbox: [0], boolean: true, scale: 3, textarea: "", url: "" };
    const answers = TEMPLATES[name].questions.filter((x) => x.required).map((x) => ({ questionId: x.id, value: sample[x.type] }));
    assert.equal(validateAnswers(TEMPLATES[name].questions, answers), null, name + ": required answers validate");
    const s = c.formSummary(r.formId);
    assert.ok(s.ok && s.mine && s.canRead && s.responses === 0, name + ": formSummary for the creator");
  }
  assert.equal(TEMPLATES.feedback.anonymous, true);
  assert.throws(() => template("bookin"), /unknown template/);
  const a = template("guestlist"); a.questions[0].text = "changed";
  assert.notEqual(TEMPLATES.guestlist.questions[0].text, "changed", "template() returns a copy");
});
