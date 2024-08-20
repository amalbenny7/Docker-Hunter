import React, { useState } from "react";
import { AiFillEye, AiOutlineEyeInvisible } from "react-icons/ai";
import InputWrapper from "../../Utils/InputWrapper";

function PasswordInput(props) {
  const { register, error, ...rest } = props;
  const [showPassword, setShowPassword] = useState(false);

  return (
    <InputWrapper error={error}>
      <div className="flex items-center">
        <input
          type={showPassword ? "text" : "password"}
          {...rest}
          {...register(rest.name)}
          //   autoComplete="off"
          className=" rounded text-buttonPrimary placeholder:text-placeholder-ash border-0  w-full outline-none p-2 pr-1"
        />
        <div
          className="mr-2 cursor-pointer"
          onClick={() => setShowPassword((prev) => !prev)}
        >
          {showPassword ? (
            <AiOutlineEyeInvisible className=" text-buttonPrimary" size={20} />
          ) : (
            <AiFillEye className=" text-buttonPrimary" size={20} />
          )}
        </div>
      </div>
    </InputWrapper>
  );
}

export default PasswordInput;
