import React, { useEffect } from "react";
import Navbar from "./Navbar";
import Footer from "./Footer";
import { Helmet } from "react-helmet";

const Layout = ({ children }) => {
  // Move the useEffect inside the component
  useEffect(() => {
    const getCSRFToken = () => {
      const csrfMetaTag = document.querySelector("meta[name='csrf-token']");
      return csrfMetaTag ? csrfMetaTag.content : "";
    };

    const csrfToken = getCSRFToken();
    if (csrfToken) {
      window.CSRF_TOKEN = csrfToken;
    } else {
      console.error("CSRF token not found");
    }
  }, []); // Empty dependency array ensures this runs only once on mount

  return (
    <div className="font-poppins bg-gray-900 text-white min-h-screen flex flex-col dark:bg-gray-900 dark:text-white">
      <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css"
      />
      <Helmet>
        <meta name="csrf-token" content={window.CSRF_TOKEN || ""} />
      </Helmet>
      <Navbar />
      <main className="flex-grow pt-16 relative z-10">{children}</main>
      <Footer />
    </div>
  );
};

export default Layout;