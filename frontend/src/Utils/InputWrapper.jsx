import React from "react";

function InputWrapper(props) {
  const { error, classname } = props;

  return (
    <div className={`${classname ? classname : " "} `}>
      <div
        className={`rounded border focus-within:border-0 focus-within:border-solid focus-within:border-buttonPrimary border-placeholder-ash transition-colors duration-150 ${
          error ? "!border-red-500" : " "
        }`}
      >
        <div
          className={`rounded border focus-within:border-2 focus-within:border-solid focus-within:border-buttonPrimary box-border border-transparent transition-colors duration-150 ${
            error ? "!border-red-500" : " "
          }`}
        >
          {props.children}
        </div>
      </div>
      {error ? (
        <p className="text-red-500 text-left pt-[2px] pl-[2px] font-normal text-xs capitalize">
          {error.message}
        </p>
      ) : null}
    </div>
  );
}

export default InputWrapper;
