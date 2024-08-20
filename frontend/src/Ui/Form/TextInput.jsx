import React from "react";
import InputWrapper from "../../Utils/InputWrapper";

function TextInput(props) {
  const { error, endAdornment, classname, register, ...rest } = props;

  return (
    <InputWrapper error={error} classname={classname}>
      <div className="flex items-center">
        <input
          type="text"
          autoComplete="off"
          {...(register && register(rest.name))}
          {...rest}
          className=" rounded text-buttonPrimary placeholder:text-placeholder-ash border-0  w-full outline-none p-2"
        />
        {endAdornment ? (
          <div className="mr-2 cursor-pointer">{endAdornment}</div>
        ) : (
          " "
        )}
      </div>
    </InputWrapper>
  );
}

export default TextInput;
