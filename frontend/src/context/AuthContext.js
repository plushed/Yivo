import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import axiosInstance from "../utils/AxiosInstance";

const AuthContext = createContext();

export const useAuth = () => {
  return useContext(AuthContext);
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);

  const getAccessToken = () => {
    return localStorage.getItem("access_token");
  };

  const getRefreshToken = () => {
    return localStorage.getItem("refresh_token");
  };

  const refreshAccessToken = useCallback(async () => {
    const refreshToken = getRefreshToken();
    if (refreshToken) {
      try {
        const response = await axiosInstance.post("https://fluffy-waffle-4xvwj5g4xvc5jwr-8000.app.github.dev/api/token/refresh/", { refresh: refreshToken });
        const { access, refresh } = response.data;
        localStorage.setItem("access_token", access);
        localStorage.setItem("refresh_token", refresh);
        return access;
      } catch (error) {
        console.error("Failed to refresh token:", error);
        return null;
      }
    }
    return null;
  }, []);

  useEffect(() => {
    const fetchUser = async () => {
      let token = getAccessToken();
      if (token) {
        try {
          const response = await axiosInstance.get("https://fluffy-waffle-4xvwj5g4xvc5jwr-8000.app.github.dev/api/accounts/user/", {
            headers: { Authorization: `Bearer ${token}` },
          });
          setUser(response.data);
          setIsAuthenticated(true);
        } catch (error) {
          if (error.response?.status === 401) {
            token = await refreshAccessToken();
            if (token) {
              fetchUser();
            } else {
              localStorage.clear();
              setIsAuthenticated(false);
            }
          } else {
            localStorage.clear();
            setIsAuthenticated(false);
          }
        }
      } else {
        setIsAuthenticated(false);
      }
      setLoading(false);
    };

    fetchUser();
  }, [refreshAccessToken]);

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
    localStorage.setItem("user", JSON.stringify(user));
    localStorage.setItem("access_token", access);
    localStorage.setItem("refresh_token", refresh);
  };
   

  const logout = () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    localStorage.removeItem("user");
    setUser(null);
    setIsAuthenticated(false);
  };

  return (
    <AuthContext.Provider value={{ user, setUser, login, logout, isAuthenticated, loading }}>
      {children}
    </AuthContext.Provider>
  );
};
