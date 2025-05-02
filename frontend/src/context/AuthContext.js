import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import axiosInstance from "../utils/AxiosInstance";

const AuthContext = createContext();

export const useAuth = () => {
  return useContext(AuthContext);
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [accessToken, setAccessToken] = useState(localStorage.getItem("access_token"));
  const [refreshToken, setRefreshToken] = useState(localStorage.getItem("refresh_token"));
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem("access_token"));
  const [loading, setLoading] = useState(true);

  const refreshAccessToken = useCallback(async () => {
    if (refreshToken) {
      try {
        const response = await axiosInstance.post(
          "https://fluffy-waffle-4xvwj5g4xvc5jwr-8000.app.github.dev/api/token/refresh/",
          { refresh: refreshToken }
        );
        const { access, refresh } = response.data;
        localStorage.setItem("access_token", access);
        localStorage.setItem("refresh_token", refresh);
        setAccessToken(access);
        setRefreshToken(refresh);
        return access;
      } catch (error) {
        console.error("Failed to refresh token:", error);
        return null;
      }
    }
    return null;
  }, [refreshToken]);

  useEffect(() => {
    const fetchUser = async () => {
      if (accessToken) {
        try {
          const response = await axiosInstance.get(
            "https://fluffy-waffle-4xvwj5g4xvc5jwr-8000.app.github.dev/api/accounts/user/",
            {
              headers: { Authorization: `Bearer ${accessToken}` },
            }
          );
          setUser(response.data);
          setIsAuthenticated(true);
        } catch (error) {
          if (error.response?.status === 401) {
            const newToken = await refreshAccessToken();
            if (newToken) {
              setAccessToken(newToken);
              fetchUser(); // retry after refresh
            } else {
              logout();
            }
          } else {
            logout();
          }
        }
      } else {
        setIsAuthenticated(false);
      }
      setLoading(false);
    };

    fetchUser();
  }, [accessToken, refreshAccessToken]);

  const login = async (email, password) => {
    const response = await axiosInstance.post(
      "https://fluffy-waffle-4xvwj5g4xvc5jwr-8000.app.github.dev/api/accounts/login/",
      { email, password }
    );

    const { access, refresh } = response.data;

    // Decode token to extract user info
    let tokenPayload = {};
    try {
      const base64Url = access.split(".")[1];
      const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
      tokenPayload = JSON.parse(atob(base64));
    } catch (e) {
      console.warn("Unable to decode token payload");
    }

    const user = {
      username: tokenPayload.username || "user",
      email: tokenPayload.email || email,
    };

    setUser(user);
    setAccessToken(access);
    setRefreshToken(refresh);
    setIsAuthenticated(true);

    localStorage.setItem("user", JSON.stringify(user));
    localStorage.setItem("access_token", access);
    localStorage.setItem("refresh_token", refresh);
  };

  const logout = () => {
    localStorage.clear();
    setUser(null);
    setAccessToken(null);
    setRefreshToken(null);
    setIsAuthenticated(false);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        accessToken,
        refreshToken,
        setUser,
        login,
        logout,
        isAuthenticated,
        loading,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
