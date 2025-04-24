import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";

const ProfileSettings = () => {
  const { user, logout, loading } = useAuth();
  const navigate = useNavigate();

  const [passwords, setPasswords] = useState({
    current_password: "",
    new_password: "",
  });

  const [feedback, setFeedback] = useState("");

  if (loading) return <div>Loading...</div>;
  if (!user) return <div>User not found. Please log in again.</div>;

  const handlePasswordChange = async () => {
    try {
      const response = await fetch("https://fluffy-waffle-4xvwj5g4xvc5jwr-8000.app.github.dev/api/accounts/change-password/", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token")}`,
        },
        body: JSON.stringify(passwords),
      });

      const data = await response.json();

      if (response.ok) {
        setFeedback("Password changed successfully.");
        setPasswords({ current_password: "", new_password: "" });
      } else {
        setFeedback(data.detail || "Password change failed.");
      }
    } catch (err) {
      console.error("Error changing password:", err);
      setFeedback("An error occurred while changing the password.");
    }
  };

  const handleDeleteAccount = async () => {
    const confirmed = window.confirm("Are you sure you want to delete your account? This action cannot be undone.");
    if (!confirmed) return;

    try {
      const response = await fetch("https://fluffy-waffle-4xvwj5g4xvc5jwr-8000.app.github.dev/api/accounts/delete-account/", {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token")}`,
        },
      });

      if (response.ok) {
        logout();
        navigate("/");
      } else {
        console.error("Account deletion failed.");
        setFeedback("Failed to delete account.");
      }
    } catch (err) {
      console.error("Error deleting account:", err);
      setFeedback("An error occurred while deleting the account.");
    }
  };

  return (
    <div className="max-w-xl mx-auto mt-10 p-6 bg-gray-900 text-white rounded-2xl shadow-md space-y-6">
      <h2 className="text-2xl font-bold mb-4">Profile Settings</h2>

      <div className="bg-gray-800 p-4 rounded-xl shadow-inner">
        <p className="text-gray-300 text-sm mb-2">Email</p>
        <p className="text-white font-medium">{user.email}</p>
      </div>

      <div className="space-y-4">
        <div className="bg-gray-800 p-4 rounded-xl shadow-inner">
          <label className="block mb-2 text-gray-300 text-sm">Current Password</label>
          <input
            type="password"
            className="w-full p-2 rounded bg-gray-700 text-white"
            value={passwords.current_password}
            onChange={(e) => setPasswords({ ...passwords, current_password: e.target.value })}
          />

          <label className="block mt-4 mb-2 text-gray-300 text-sm">New Password</label>
          <input
            type="password"
            className="w-full p-2 rounded bg-gray-700 text-white"
            value={passwords.new_password}
            onChange={(e) => setPasswords({ ...passwords, new_password: e.target.value })}
          />

          <button
            onClick={handlePasswordChange}
            className="mt-4 bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-xl transition"
          >
            Change Password
          </button>
        </div>

        <div className="flex justify-between">
          <button
            onClick={handleDeleteAccount}
            className="bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded-xl transition"
          >
            Delete Account
          </button>
        </div>

        {feedback && <p className="text-sm text-yellow-400 mt-2">{feedback}</p>}
      </div>
    </div>
  );
};

export default ProfileSettings;
