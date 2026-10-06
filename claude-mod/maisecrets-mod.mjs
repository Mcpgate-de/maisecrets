// maisecrets as a Claude Code mod (Claude Code 2.1.287 and later). A prompt with a secret or
// personal data goes through with placeholders in place of the values, instead of being blocked
// and sent again. The detection is the plugin's own (hooks/dispatch.py mod-prompt), not a copy.
//
// The settings hook in hooks/hooks.json stays the gate. It runs after this mod, on the text the
// mod passes on. Whenever the mod gives no rewrite (it does not load, the launcher fails, the
// answer has another shape, the hook times out), the prompt reaches that hook unchanged and the
// hook blocks it as without the mod. So no path here may pass on a value.

const MARK = 'mod-prompt'
// a person's own prompt: typed or queued at the terminal, sent through Remote Control, or the turn of
// claude -p. A subagent's report, a peer's or a channel's message stays with the settings hook (C19)
const PERSON = new Set(['composer', 'bridge', 'sdk'])

async function ask($, prompt, session, cwd) {
  const stdin = JSON.stringify({ prompt, session_id: session, cwd })
  // the plugin's own launcher, as fixed text, run in the plugin folder: no shell, and nothing but this
  // computer's own Python gets the prompt (README, "The mod")
  const init = { cwd: $.plugin.root, stdin, timeoutMs: 8000 }
  const r = (await $.env.get('OS')) === 'Windows_NT'
    ? await $.process.run(['cmd.exe', '/d', '/c', 'hooks\\run.cmd', 'mod-prompt'], init)
    : await $.process.run(['bash', 'hooks/run.sh', 'mod-prompt'], init)
  if (r.exitCode !== 0) return null
  const answer = JSON.parse(r.stdout)
  if (!answer || answer.maisecrets !== MARK || typeof answer.text !== 'string') return null
  return answer
}

export function register(on) {
  on('prompt.submit', async ($, e, next) => {
    if (!PERSON.has(e.origin?.kind)) return next(e)
    let answer = null
    try {
      answer = await ask($, e.text, await $.session.id(), await $.session.cwd())
    } catch {
      // the hook decides it
    }
    if (!answer) return next(e)
    try {
      $.ui.log(`replaced ${answer.count} value(s) with placeholders before the prompt was sent`)
    } catch {
      // a line for the person only; the rewrite does not depend on it
    }
    return next({ ...e, text: answer.text })
  }).catch(async ($, e, next) => {
    // the hook above threw or timed out before it passed the prompt on: the prompt goes on unchanged,
    // to the settings hook, which decides it as without the mod
    if (!next.called) return next(e)
    // it failed after it had passed the prompt on: nothing is sent a second time
    return { drop: 'maisecrets could not finish its check of this prompt. Send it again.' }
  })
}
