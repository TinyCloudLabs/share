import { useState } from "react";

export default function Counter() {
  const [count, setCount] = useState(0);
  return (
    <main style={{ fontFamily: "system-ui", padding: "2rem" }}>
      <h1 id="title">Q3 agent report</h1>
      <p>Clicked {count} times</p>
      <button id="inc" type="button" onClick={() => setCount(count + 1)}>Add one</button>
    </main>
  );
}
