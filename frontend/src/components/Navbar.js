import React, { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { UserCircle } from "lucide-react";

const Navbar = () => {
  const { user, isAuthenticated, logout, loading } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <nav className="fixed top-0 inset-x-0 z-50 bg-gray-900 shadow-sm border-b border-gray-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex h-16 justify-between items-center">
          {/* Logo */}
          <div className="flex-shrink-0">
            <Link
              to="/"
              className="text-lg font-bold text-white hover:text-purple-400"
            >
              Yivo
            </Link>
          </div>

          {/* Desktop Menu */}
          <div className="hidden lg:flex space-x-6 items-center">
            <Link to="/" className="text-sm font-medium text-gray-300 hover:text-purple-400 transition">
              Home
            </Link>
            <Link to="/about" className="text-sm font-medium text-gray-300 hover:text-purple-400 transition">
              About
            </Link>
            {!loading && isAuthenticated && (
              <>
                <Link to="/search" className="text-sm font-medium text-gray-300 hover:text-purple-400 transition">
                  Search
                </Link>
                <Link to="/discover" className="text-sm font-medium text-gray-300 hover:text-purple-400 transition">
                  Discover
                </Link>
                <Link to="/dashboard" className="text-sm font-medium text-gray-300 hover:text-purple-400 transition">
                  Dashboard
                </Link>
                <Link to="/settings" className="text-sm font-medium text-gray-300 hover:text-purple-400 transition">
                  Settings
                </Link>
              </>
            )}
          </div>

          {/* User section */}
          <div className="hidden lg:flex items-center space-x-4">
            {isAuthenticated && user ? (
              <div className="flex items-center space-x-2 text-sm text-gray-300">
                <span>{user.email}</span>
                <UserCircle className="h-6 w-6 text-purple-400" />
                <button
                  onClick={logout}
                  className="text-red-400 hover:text-red-600 text-sm font-medium"
                >
                  Logout
                </button>
              </div>
            ) : (
              !loading && (
                <>
                  <Link to="/login" className="text-sm font-medium text-gray-300 hover:text-purple-400 transition">
                    Login
                  </Link>
                  <Link to="/register" className="text-sm font-medium text-gray-300 hover:text-purple-400 transition">
                    Sign Up
                  </Link>
                </>
              )
            )}
          </div>

          {/* Mobile menu button */}
          <div className="flex lg:hidden">
            <button
              onClick={() => setMenuOpen(!menuOpen)}
              className="text-gray-400 hover:text-white focus:outline-none"
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
                  d="M4 6h16M4 12h16M4 18h16"
                />
              </svg>
            </button>
          </div>
        </div>
      </div>

      {/* Mobile menu */}
      {menuOpen && (
        <div className="lg:hidden bg-gray-900 px-4 pt-2 pb-4 space-y-1">
          <Link to="/" className="block text-sm font-medium text-gray-300 hover:text-purple-400 transition">
            Home
          </Link>
          <Link to="/about" className="block text-sm font-medium text-gray-300 hover:text-purple-400 transition">
            About
          </Link>
          {!loading && isAuthenticated && (
            <>
              <Link to="/search" className="block text-sm font-medium text-gray-300 hover:text-purple-400 transition">
                Search
              </Link>
              <Link to="/discover" className="block text-sm font-medium text-gray-300 hover:text-purple-400 transition">
                Discover
              </Link>
              <Link to="/dashboard" className="block text-sm font-medium text-gray-300 hover:text-purple-400 transition">
                Dashboard
              </Link>
              <Link to="/settings" className="block text-sm font-medium text-gray-300 hover:text-purple-400 transition">
                Settings
              </Link>
              <button
                onClick={logout}
                className="block w-full text-left text-sm font-medium text-red-400 hover:text-red-600 transition"
              >
                Logout
              </button>
            </>
          )}
          {!loading && !isAuthenticated && (
            <>
              <Link to="/login" className="block text-sm font-medium text-gray-300 hover:text-purple-400 transition">
                Login
              </Link>
              <Link to="/register" className="block text-sm font-medium text-gray-300 hover:text-purple-400 transition">
                Sign Up
              </Link>
            </>
          )}
        </div>
      )}
    </nav>
  );
};

export default Navbar;
