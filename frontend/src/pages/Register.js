import React, { useState } from "react";
import axiosInstance from "../utils/AxiosInstance";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const Register = () => {
  const { setUser } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");

  // Reset error when the user starts typing again
  const handleInputChange = (setter) => (e) => {
    setter(e.target.value);
    setError("");
  };

  const handleRegister = async (e) => {
    e.preventDefault();

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (!/[A-Z]/.test(password) || !/[0-9]/.test(password) || password.length < 8) {
      setError("Password must be at least 8 characters, contain a number, and an uppercase letter.");
      return;
    }

    const userData = { username, email, password };

    try {
      const response = await axiosInstance.post("https://fluffy-waffle-4xvwj5g4xvc5jwr-8000.app.github.dev/api/accounts/register/", userData);
      const data = response.data;

      const newUser = { email: data.email, username: data.username };
      setUser(newUser);
      localStorage.setItem("user", JSON.stringify(newUser));
      navigate("/dashboard");
    } catch (err) {
      const errorMsg = err.response?.data?.detail || "An error occurred during registration.";
      setError(errorMsg);
      console.error(err);
    }
  };

  return (
    <div className="flex flex-col justify-center items-center h-screen">
      <h1 className="text-4xl font-bold text-purple-500">Register</h1>
      <form onSubmit={handleRegister} className="space-y-4 mt-8 w-72">
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={handleInputChange(setUsername)}
          className="w-full p-2 bg-gray-800 text-white border border-gray-700 rounded"
          required
        />
        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={handleInputChange(setEmail)}
          className="w-full p-2 bg-gray-800 text-white border border-gray-700 rounded"
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={handleInputChange(setPassword)}
          className="w-full p-2 bg-gray-800 text-white border border-gray-700 rounded"
          required
        />
        <input
          type="password"
          placeholder="Confirm Password"
          value={confirmPassword}
          onChange={handleInputChange(setConfirmPassword)}
          className="w-full p-2 bg-gray-800 text-white border border-gray-700 rounded"
          required
        />
        {error && <p className="text-red-500 text-sm">{error}</p>}
        <button
          type="submit"
          className="w-full py-2 px-4 bg-purple-600 text-white rounded hover:bg-purple-700"
        >
          Register
        </button>
      </form>
    </div>
  );
};

export default Register;
