import React, { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const Navbar = () => {
  const { user, isAuthenticated, logout, loading } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <nav className="absolute top-0 left-0 w-full z-50 bg-gray-900 text-white">
      <div className="container mx-auto px-4 py-3 flex justify-between items-center">
        {/* Brand */}
        <Link
          to="/"
          className="text-lg font-bold text-white hover:text-purple-400"
        >
          Yivo
        </Link>

        {/* Mobile Menu Toggle */}
        <button
          className="lg:hidden text-white hover:text-purple-400 focus:outline-none"
          onClick={() => setMenuOpen(!menuOpen)}
        >
          <svg
            className="w-6 h-6"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M4 6h16M4 12h16m-7 6h7"
            />
          </svg>
        </button>

        {/* Right Side Info */}
        <div className="hidden lg:flex items-center space-x-4">
          {isAuthenticated && user ? (
            <span className="text-sm font-medium">
              Logged in as, {user.email}
            </span>
          ) : null}
        </div>
      </div>

      {/* Navbar Links */}
      <div
        className={`lg:flex lg:items-center lg:space-x-6 px-4 py-2 transition-all duration-200 bg-gray-900 ${
          menuOpen ? "block" : "hidden"
        }`}
      >
        <Link to="/" className="block px-2 py-1 hover:text-purple-400">
          Home
        </Link>
        <Link to="/about" className="block px-2 py-1 hover:text-purple-400">
          About
        </Link>
        {!loading && (
          isAuthenticated ? (
            <>
              <Link to="/search" className="block px-2 py-1 hover:text-purple-400">Search</Link>
              <Link to="/discover" className="block px-2 py-1 hover:text-purple-400">Discover</Link>
              <Link to="/dashboard" className="block px-2 py-1 hover:text-purple-400">Dashboard</Link>
              <Link to="/settings" className="block px-2 py-1 hover:text-purple-400">Settings</Link>
              <button
                onClick={logout}
                className="block px-2 py-1 text-red-400 hover:text-red-600"
              >
                Logout
              </button>
            </>
          ) : (
            <>
              <Link to="/login" className="block px-2 py-1 hover:text-purple-400">Login</Link>
              <Link to="/register" className="block px-2 py-1 hover:text-purple-400">Sign Up</Link>
            </>
          )
        )}
      </div>
    </nav>
  );
};

export default Navbar;
