import React, { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { yupResolver } from "@hookform/resolvers/yup";
import * as yup from "yup";
import Button from "../../Ui/Button/Button";
import PasswordInput from "../../Ui/Form/PasswordInput";
import TextInput from "../../Ui/Form/TextInput";
import { IoIosArrowDroprightCircle } from "react-icons/io";
import _ from "lodash";
import { useDispatch, useSelector } from "react-redux";
import { loginUser, resetError } from "../../redux/Features/Auth/authSlice";
import { useNavigate, useLocation } from "react-router-dom";

function Login(props) {
  const { onSwitchState } = props;
  const dispatch = useDispatch();
  const navigate = useNavigate();

  const { isLoading, error, status, formSubmitted } = useSelector(
    (store) => store.auth
  );

  const schema = yup.object().shape({
    email: yup.string().email().required(),
    password: yup.string().min(8).required(),
  });

  useEffect(() => {
    if (!(status === "succeeded")) return;
    navigate("/");
  }, [isLoading, error, status]);

  const {
    register,
    handleSubmit,
    formState: { errors, isDirty, isValid },
  } = useForm({
    resolver: yupResolver(schema),
    mode: "onChange",
  });

  const login = (e) => {
    dispatch(loginUser({ email: e.email, password: e.password }));
  };

  const formOnChangeHanlder = (e) => {
    e.preventDefault();
    if (error) {
      dispatch(resetError());
    }
  };

  return (
    <>
      <div className="w-full ">
        <form
          className=" space-y-4"
          onSubmit={handleSubmit(login)}
          onChange={(e) => formOnChangeHanlder(e)}
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
          <div className=" text-center">
            <Button
              primary={true}
              classname={"px-8 py-2 font-semibold text-sm"}
              isButton={true}
              disabled={!isDirty || !isValid || !_.isEmpty(error) || isLoading}
            >
              <div className=" flex gap-1 items-center">
                <span>Login</span>
                <IoIosArrowDroprightCircle className=" inline-block text-my-ebonyClay-400" />
              </div>
            </Button>
          </div>
          {formSubmitted && error ? (
            <p className=" text-red-500  uppercase text-xs">{error}</p>
          ) : (
            " "
          )}
          <p className="uppercase text-xs text-buttonPrimary">
            New to Bug Hunter?{" "}
            <span
              className=" text-secondary underline cursor-pointer hover:text-buttonPrimary"
              onClick={() => onSwitchState()}
            >
              Create an account.
            </span>
          </p>
        </form>
      </div>
    </>
  );
}

export default Login;
