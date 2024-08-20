import React from "react";

import Navbar from "../Components/Navbar";
import Footer from "../Components/Footer";
import { SnackbarProvider } from "notistack";
import { Outlet } from "react-router-dom";

function AuthLayout() {
  return (
    <div className="flex flex-col min-h-screen h-screen w-full">
      <Navbar />
      <SnackbarProvider maxSnack={3} />
      <div className="flex-grow h-full">
        <div className="flex flex-row h-full">
          <div className=" bg-white p-4 w-full">
            <Outlet />
          </div>
        </div>
      </div>
      {/* <Footer /> */}
    </div>
  );
}

export default AuthLayout;
