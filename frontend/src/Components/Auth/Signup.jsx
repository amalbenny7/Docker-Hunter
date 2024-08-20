import React, { useEffect } from "react";
import { useForm } from "react-hook-form";
import { yupResolver } from "@hookform/resolvers/yup";
import * as yup from "yup";
import YupPassword from "yup-password";
import Button from "../../Ui/Button/Button";

import { IoIosArrowDroprightCircle } from "react-icons/io";
import _ from "lodash";
import PasswordInput from "../../Ui/Form/PasswordInput";
import TextInput from "../../Ui/Form/TextInput";
import { useSelector, useDispatch } from "react-redux";
import { useNavigate, useLocation } from "react-router-dom";
import { signUpUser, resetError } from "../../redux/Features/Auth/authSlice";

YupPassword(yup);

function Signup(props) {
  const { onSwitchState } = props;
  const navigate = useNavigate();
  const location = useLocation();
  const dispatch = useDispatch();
  const { isLoading, error, status, formSubmitted } = useSelector(
    (store) => store.auth
  );

  const schema = yup.object().shape({
    email: yup.string().email().required(),
    password: yup
      .string()
      .min(8)
      .minLowercase(1)
      .minNumbers(1)
      .minSymbols(1)
      .minUppercase(1),
    confirmPassword: yup
      .string()
      .oneOf([yup.ref("password")], "Password doesnt Match"),
  });

  useEffect(() => {
    if (!(status === "succeeded")) return;
    navigate(`${location.pathname}/create-uername`);
  }, [isLoading, error, status]);

  const {
    register,
    handleSubmit,
    formState: { errors, isDirty, isValid },
  } = useForm({
    mode: "onChange",
    resolver: yupResolver(schema),
  });

  const signUp = (data) => {
    dispatch(
      signUpUser({
        email: data.email,
        password: data.password,
        confirmPassword: data.confirmPassword,
      })
    );
  };

  const onChangeHanlder = (e) => {
    e.preventDefault();
    if (error) {
      dispatch(resetError());
    }
  };

  return (
    <>
      <div className="w-full ">
        <form
          className="space-y-4"
          onChange={(e) => onChangeHanlder(e)}
          onSubmit={handleSubmit(signUp)}
        >
          <TextInput
            placeholder="Email"
            name="email"
            type="text"
            register={register}
            error={_.isEmpty(errors) ? null : errors.email}
          />
          <PasswordInput
            placeholder="Password"
            name="password"
            register={register}
            error={_.isEmpty(errors) ? null : errors.password}
          />
          <PasswordInput
            placeholder="Confirm Password"
            name="confirmPassword"
            register={register}
            error={_.isEmpty(errors) ? null : errors.confirmPassword}
          />
          <div className=" text-center">
            <Button
              primary={true}
              classname={"px-8 py-2 font-semibold text-sm"}
              isButton={true}
              disabled={!isDirty || !isValid || !_.isEmpty(error) || isLoading}
            >
              <div className=" flex gap-1 items-center">
                <span>Sign Up</span>
                <IoIosArrowDroprightCircle className=" inline-block text-my-ebonyClay-400" />
              </div>
            </Button>
          </div>
          {formSubmitted && error ? (
            <p className=" text-red-500  uppercase text-xs">{error}</p>
          ) : (
            " "
          )}
          <p
            className=" text-buttonPrimary uppercase text-xs"
            onClick={() => onSwitchState()}
          >
            Already have an account?{" "}
            <span className="text-secondary underline cursor-pointer hover:text-buttonPrimary">
              Login
            </span>
          </p>
        </form>
      </div>
    </>
  );
}

//

export default Signup;
