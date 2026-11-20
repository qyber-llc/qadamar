import Qadamar.Json

/-- Reads JSON lines on stdin (`{ bundle, cases: [{ request, oracle }] }`), writes one JSON line of decisions each. -/
partial def loop (stdin : IO.FS.Stream) (stdout : IO.FS.Stream) : IO Unit := do
  let line ← stdin.getLine
  if line.isEmpty then return
  let t := line.trimAscii.toString
  unless t.isEmpty do
    stdout.putStrLn (Qadamar.runLine t).compress
    stdout.flush
  loop stdin stdout

def main : IO Unit := do
  loop (← IO.getStdin) (← IO.getStdout)
