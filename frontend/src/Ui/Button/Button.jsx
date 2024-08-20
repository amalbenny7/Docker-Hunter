import React from "react";

function Button(props) {
  const { primary, children, classname, isButton, ...rest } = props;
  return (
    <>
      {isButton ? (
        <button
          type="submit"
          className={`px-4 py-2 inline-block border-none no-underline rounded-full font-medium cursor-pointer disabled:opacity-25${
            primary ? " bg-buttonPrimary text-white" : " "
          } ${classname ? classname : " "}`}
          {...rest}
        >
          {children}
        </button>
      ) : (
        <a
          className={`px-4 py-2 inline-block border-none no-underline rounded-full font-medium cursor-pointer disabled:opacity-25 ${
            primary ? " bg-buttonPrimary  text-white" : " "
          } ${classname ? classname : " "}`}
          href="#"
          {...rest}
        >
          {children}
        </a>
      )}
    </>
  );
}

export default Button;
