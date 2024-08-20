import "./App.css";

import { Routes, Route, useNavigate } from "react-router-dom";
import Layout from "./Pages/Layout";

import AuthLayout from "./Pages/AuthLayout";
import Authenticate from "./Components/Auth";
import AddUsername from "./Components/AddUsername/AddUsername";

import Home from "./Pages/Home";
import { useEffect } from "react";
import { getRefreshToken, getUser } from "./redux/Features/Auth/authSlice";
import { useDispatch, useSelector } from "react-redux";
import Issue from "./Pages/Issue";
import Issues from "./Pages/Issues";

function App() {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const { user, isGettingUserOrToken } = useSelector((store) => store.auth);

  useEffect(() => {
    const checkTokenExpiration = async () => {
      const refreshToken = localStorage.getItem("refreshToken");
      if (!refreshToken || refreshToken.length === 0) return;

      const tokenExpiration = localStorage.getItem("expires_in");
      const currentTime = Math.floor(Date.now() / 1000);

      if (tokenExpiration && currentTime > tokenExpiration) {
        dispatch(getRefreshToken(refreshToken)).then((res) => {
          if (!res.payload.data.status) {
            navigate("/auth");
          }
        });
      }
    };

    const runTokenChecks = async () => {
      const accessToken = localStorage.getItem("accessToken");

      if (!(accessToken && accessToken.length > 0)) {
        navigate("/auth");
        return;
      }
      await checkTokenExpiration();

      if (accessToken && accessToken.length > 0) {
        dispatch(getUser(accessToken)).then((res) => {
          if (!res.payload.data.status) {
            navigate("/auth");
          }
        });
      } else {
        // dispatch(markIsAuthencated({ isAuthenticated: false }));
      }
    };

    runTokenChecks();
  }, []);

  useEffect(() => {
    if (user.isLoggedIn && user.username === null) {
      navigate("/auth/create-uername");
    }
  }, [user]);

  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Home />} />
        <Route path="issue/:issueKey" element={<Issue />} />
        <Route path="issues" element={<Issues />} />
        <Route path="*" element={<h1>No Match Found</h1>} />
      </Route>
      <Route path="/auth" element={<AuthLayout />}>
        <Route index element={<Authenticate />} />
        <Route path="create-uername" element={<AddUsername />} />
      </Route>
    </Routes>
  );
}

export default App;
