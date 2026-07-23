/**
 * The first executable on the viewer route. It captures the link once and
 * removes every fragment-bearing history entry before importing the app.
 * Nothing imported here may perform I/O or observe the original URL.
 */
import { captureAndScrubLaunch } from "../email-share/url.js";

const launch = captureAndScrubLaunch(window.location, window.history);
void import("./main.js").then(({ bootDefault }) => bootDefault(launch));
