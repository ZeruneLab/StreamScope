import App from "./App";
import "./plugin-ui.css";

// Presentation belongs to the host; analysis still belongs to installed plugins.
export default function CoreApp() {
  return <App coreOnly />;
}
