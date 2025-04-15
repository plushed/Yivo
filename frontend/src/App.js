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
import NotFound from "./pages/NotFound";
import { AuthProvider, useAuth } from "./context/AuthContext"; // Ensure useAuth is being imported
import ModuleSettings from "./pages/ModuleSettings";

function App() {
  return (
    <AuthProvider>
      <Router>
        <Layout>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/about" element={<About />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/module-settings" element={<ModuleSettings />} />

            {/* Protected routes */}
            <Route
              path="/search"
              element={<ProtectedRoute component={Search} />}
            />
            <Route
              path="/discover"
              element={<ProtectedRoute component={Discover} />}
            />
            <Route
              path="/dashboard"
              element={<ProtectedRoute component={Dashboard} />}
            />

            <Route path="*" element={<NotFound />} />
          </Routes>
        </Layout>
      </Router>
    </AuthProvider>
  );
}

// Protected route component
const ProtectedRoute = ({ component: Component }) => {
  const { user } = useAuth();  // Using the context to check user state

  return user ? <Component /> : <Navigate to="/login" />;
};

export default App;
