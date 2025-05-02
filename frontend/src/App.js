import React from "react";
import { BrowserRouter as Router, Route, Routes, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import Home from "./pages/Home";
import About from "./pages/About";
import Search from "./pages/Search";
import Discover from "./pages/Discover";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import SettingsPage from "./pages/Settings";
import NotFound from "./pages/NotFound";
import { AuthProvider, useAuth } from "./context/AuthContext";

// Protected route wrapper
const ProtectedRoute = ({ component: Component, pageTitle }) => {
  const { user } = useAuth();
  return user ? (
    <Layout pageTitle={pageTitle}>
      <Component />
    </Layout>
  ) : (
    <Navigate to="/login" />
  );
};

function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          {/* Public routes */}
          <Route path="/" element={<Layout><Home /></Layout>} />
          <Route path="/about" element={<Layout pageTitle="About"><About /></Layout>} />
          <Route path="/login" element={<Layout><Login /></Layout>} />
          <Route path="/register" element={<Layout><Register /></Layout>} />

          {/* Protected routes with pageTitle headers */}
          <Route path="/settings" element={<ProtectedRoute component={SettingsPage} pageTitle="Settings" />} />
          <Route path="/search" element={<ProtectedRoute component={Search} pageTitle="Search" />} />
          <Route path="/discover" element={<ProtectedRoute component={Discover} pageTitle="Discover" />} />
          <Route path="/dashboard" element={<ProtectedRoute component={Dashboard} pageTitle="Dashboard" />} />

          <Route path="*" element={<Layout><NotFound /></Layout>} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;
