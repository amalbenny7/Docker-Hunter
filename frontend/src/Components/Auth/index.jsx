import React from "react";
import Login from "./Login";
import Signup from "./Signup";
import useToggle from "../../Utils/useToggle";
import AuthCard from "./AuthCard/AuthCard";
import AuthCardHeading from "./AuthCard/AuthCardHeading";

function Auth() {
  const [value, toggleValue] = useToggle(true);
  const isLogin = value;

  return (
    <div className=" flex justify-center items-center w-full h-full flex-col">
      <AuthCard>
        <AuthCardHeading>{isLogin ? "Login" : "SignUp"}</AuthCardHeading>
        {isLogin ? (
          <Login onSwitchState={toggleValue} />
        ) : (
          <Signup onSwitchState={toggleValue} />
        )}
      </AuthCard>
      {isLogin ? (
        <div className=" mt-8">
          <p className=" text-secondary  uppercase text-xs">
            Forgot Your{" "}
            <span className="cursor-pointer text-placeholder-ash underline">
              Email
            </span>
            &#47;
            <span className="cursor-pointer text-placeholder-ash underline">
              Password
            </span>
            ?
          </p>
        </div>
      ) : null}
    </div>
  );
}

// box-shadow: rgba(0, 0, 0, 0.1) 0px 4px 12px;

export default Auth;
