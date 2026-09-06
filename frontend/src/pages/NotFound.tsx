import { Navigate, useLocation } from "react-router-dom";

// Any unknown path lands the user on the dashboard rather than a dead end.
// APM access policies routinely drop users on a landing URI this app does not
// route, and a bare 404 card there looks like the app is broken.
const NotFound = () => {
  const location = useLocation();
  console.warn("Unknown route, redirecting to /:", location.pathname);
  return <Navigate to="/" replace />;
};

export default NotFound;
