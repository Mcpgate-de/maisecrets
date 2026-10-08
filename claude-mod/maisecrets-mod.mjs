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

// The plugin's own hooks/dispatch.py, started by this computer's Python, in the plugin folder: each call is
// fixed text, no shell and no environment read (the directory review asks for one program by name with fixed
// arguments). macOS and Linux have python3, Windows the py launcher or python; on Windows `python3` is often a
// store stub that starts and exits 9009. A call that cannot start or exits with an error hands on to the next
// (dispatch.py exits 3 on a Python older than 3.9); a timeout ends the search. All of them share one budget, so a
// prompt waits at most BUDGET_MS. When none answers, the settings hook blocks the prompt (README, "The mod")
const BUDGET_MS = 8000

async function runPython3($, init) {
  return await $.process.run(['python3', 'hooks/dispatch.py', 'mod-prompt'], init)
}

async function runPyLauncher($, init) {
  return await $.process.run(['py', '-3', 'hooks/dispatch.py', 'mod-prompt'], init)
}

async function runPython($, init) {
  return await $.process.run(['python', 'hooks/dispatch.py', 'mod-prompt'], init)
}

async function runDispatch($, stdin) {
  const end = Date.now() + BUDGET_MS
  for (let i = 0; i < 3; i++) {
    const left = end - Date.now()
    if (left <= 0) return null
    // UTF-8 for the pipe: Windows Python would read it in the console code page, and a prompt with umlauts failed
    const init = { cwd: $.plugin.root, stdin, timeoutMs: left, env: { PYTHONUTF8: '1' } }
    let r
    try {
      r = i === 0 ? await runPython3($, init) : i === 1 ? await runPyLauncher($, init) : await runPython($, init)
    } catch {
      if (Date.now() >= end) return null    // the budget is spent (a timeout): no second rewrite
      continue                              // this Python cannot start
    }
    if (r.exitCode === 0) return r
  }
  return null
}

async function ask($, prompt, session, cwd) {
  const r = await runDispatch($, JSON.stringify({ prompt, session_id: session, cwd }))
  if (!r) return null
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
