import React, { useEffect } from "react";
import Navbar from "./Navbar";
import Footer from "./Footer";
import { Helmet } from "react-helmet";

const Layout = ({ children, pageTitle }) => {
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
  }, []);

  return (
    <div className="font-poppins bg-gray-900 text-white min-h-screen flex flex-col">
      <Helmet>
        <meta name="csrf-token" content={window.CSRF_TOKEN || ""} />
      </Helmet>

      <Navbar />

      {/* Only render the header if pageTitle exists */}
      {pageTitle && (
      <header className="bg-gray-600 shadow w-full mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <h1 className="text-lg font-bold text-white tracking-tight py-6">
            {pageTitle}
          </h1>
        </div>
      </header>
    )}

<main className="flex-1 bg-gray-900 mt-16">
        <div className="w-full">{children}</div>
      </main>

      <Footer />
    </div>
  );
};

export default Layout;
