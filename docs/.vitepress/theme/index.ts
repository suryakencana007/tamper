// The default theme, restyled. A theme directory must export something — an empty one makes
// the build look for `theme/index` and fail, which is the first thing this file fixed.
import DefaultTheme from "vitepress/theme";
import "./styles.css";

export default DefaultTheme;
