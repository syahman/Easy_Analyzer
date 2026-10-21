export function AiLocalSummary({ text }: { text: string }) {
  return (
    <details className="local-ai-summary">
      <summary>Local result recap · partially completed</summary>
      <p>
        Only successful replies are summarized; this does not add new AI
        correlation reasoning. Full content remains in the findings list and run
        history.
      </p>
      <pre>{text}</pre>
    </details>
  );
}
