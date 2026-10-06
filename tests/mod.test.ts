// The mod's own logic (claude-mod/maisecrets-mod.mjs), run by `claude plugin test` with no session and no
// Python: $.process.run is stubbed. The rule under test: only a well-formed answer from the
// plugin's launcher changes the prompt; every other outcome passes it on unchanged, so the
// settings hook decides it (harness: prompt_secret_rewrite_off shows that hook blocks it).
import { expect, test } from 'claude-code/testing'

const TYPED = 'check TOKENWORD in CI'
const REWRITTEN = 'check ⟦SECRET_c1⟧ in CI'

function common(on, run) {
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.cwd', () => ({ value: '/work' }))
  on('env.get', () => ({ value: undefined }))
  on('ui.log', () => ({ value: undefined }))
  on('process.run', run)
  // Claude Code's own answer to a prompt: the text that arrived
  on('prompt.submit', ($, e) => ({ text: e.text }))
}

async function submit($, kind = 'composer') {
  return $.prompt.submit({ text: TYPED, wait: false, origin: { kind } })
}

test('a well-formed answer replaces the prompt', async ($, on) => {
  let seen
  common(on, ($, e) => {
    seen = e
    return { value: { exitCode: 0, stderr: '',
                      stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN, count: 1 }) } }
  })
  const r = await submit($)
  expect(r.text).toBe(REWRITTEN)
  // the plugin's own launcher, with the prompt and the session on stdin
  expect(seen.argv).toEqual(['bash', 'hooks/run.sh', 'mod-prompt'])
  expect(typeof seen.init.cwd).toBe('string')        // the plugin folder: the command line is fixed text
  expect(JSON.parse(seen.init.stdin)).toEqual({ prompt: TYPED, session_id: 'sess-1', cwd: '/work' })
})

test('no rewrite from the launcher leaves the prompt unchanged', async ($, on) => {
  common(on, () => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-prompt' }) } }))
  expect((await submit($)).text).toBe(TYPED)
})

test('a failed launcher leaves the prompt unchanged, even with a well-formed answer', async ($, on) => {
  common(on, () => ({ value: { exitCode: 1, stderr: 'boom',
                               stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN, count: 1 }) } }))
  expect((await submit($)).text).toBe(TYPED)
})

test('a launcher that cannot start leaves the prompt unchanged', async ($, on) => {
  common(on, () => ({ deny: 'cannot start' }))
  expect((await submit($)).text).toBe(TYPED)
})

test('output that is no JSON leaves the prompt unchanged', async ($, on) => {
  common(on, () => ({ value: { exitCode: 0, stderr: '', stdout: 'maisecrets needs Python 3.9' } }))
  expect((await submit($)).text).toBe(TYPED)
})

test('an answer from something else leaves the prompt unchanged', async ($, on) => {
  common(on, () => ({ value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ text: REWRITTEN }) } }))
  expect((await submit($)).text).toBe(TYPED)
})

test('a text that is no string leaves the prompt unchanged', async ($, on) => {
  common(on, () => ({ value: { exitCode: 0, stderr: '',
                               stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: { a: 1 } }) } }))
  expect((await submit($)).text).toBe(TYPED)
})

test('a person\'s prompt from Remote Control and from claude -p is rewritten too', async ($, on) => {
  common(on, () => ({ value: { exitCode: 0, stderr: '',
                               stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN, count: 1 }) } }))
  expect((await submit($, 'bridge')).text).toBe(REWRITTEN)
  expect((await submit($, 'sdk')).text).toBe(REWRITTEN)
})

test('a prompt that is not a person\'s goes on unchanged and the launcher does not run', async ($, on) => {
  let runs = 0
  common(on, () => {
    runs += 1
    return { value: { exitCode: 0, stderr: '', stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN }) } }
  })
  for (const kind of ['task-notification', 'peer', 'peer-send-message', 'channel', 'scheduled-trigger', 'unclassified']) {
    expect((await submit($, kind)).text).toBe(TYPED)
  }
  expect(runs).toBe(0)
})

test('a failure after the prompt was passed on drops it and sends nothing a second time', async ($, on) => {
  let downstream = 0
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.cwd', () => ({ value: '/work' }))
  on('env.get', () => ({ value: undefined }))
  on('ui.log', () => ({ value: undefined }))
  on('process.run', () => ({ value: { exitCode: 0, stderr: '',
                                      stdout: JSON.stringify({ maisecrets: 'mod-prompt', text: REWRITTEN, count: 1 }) } }))
  on('prompt.submit', () => {
    downstream += 1
    throw new Error('the client failed after the rewrite')
  })
  const r = await submit($)
  expect(downstream).toBe(1)
  expect(typeof r.drop).toBe('string')
})
