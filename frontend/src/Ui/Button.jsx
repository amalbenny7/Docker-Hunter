import React from "react";

function Button(props) {
  const { children, onClick, disabled, isButton, className, ...rest } = props;

  return isButton ? (
    <button
      onClick={onClick}
      type="button"
      className={`px-3 disabled:cursor-wait leading-none py-2 text-center pointer rounded bg-buttonPrimary text-white hover:opacity-80 duration-100 ${className}`}
      {...rest}
      disabled={disabled}
    >
      {children}
    </button>
  ) : (
    <a
      onClick={onClick}
      className={`px-3 leading-none py-2 inline-block text-center pointer rounded bg-buttonPrimary text-white hover:opacity-80 duration-100 ${className}`}
      {...rest}
    >
      {children}
    </a>
  );
}

export default Button;
