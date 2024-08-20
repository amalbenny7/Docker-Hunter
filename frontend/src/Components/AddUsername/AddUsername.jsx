import React, { useState, useEffect } from "react";
import { IoIosArrowDroprightCircle } from "react-icons/io";
import * as yup from "yup";
import { useForm } from "react-hook-form";
import { yupResolver } from "@hookform/resolvers/yup";
import Button from "../../Ui/Button/Button";
import TextInput from "../../Ui/Form/TextInput";
import AuthCard from "../Auth/AuthCard/AuthCard";
import AuthCardHeading from "../Auth/AuthCard/AuthCardHeading";
import CheckText from "./CheckText";
import Spinner from "../../Ui/Spinner/Spinner";
import _ from "lodash";
import { HiCheck } from "react-icons/hi";
import { useSelector, useDispatch } from "react-redux";
import { useNavigate, useLocation } from "react-router-dom";
import {
  checkUsernameIsAvailable,
  submitUsername,
  resetError,
  resetUsernameIsAvailable,
} from "../../redux/Features/Username/UsernameSlice";

function AddUsername() {
  const [displayCheck, setDisplayCheck] = useState(false);
  const [usernameChoice, setUsernameChoice] = useState(null);

  const {
    isLoading,
    error,
    status,
    user: { usernameIsAvailable, username, usernameAdded },
  } = useSelector((store) => store.createUsername);

  const dispatch = useDispatch();

  const navigate = useNavigate();

  const schema = yup.object().shape({
    username: yup
      .string()
      .trim()
      .min(6)
      .max(20)
      .test("no-period", "Username cannot contain an period", function (value) {
        return !value.includes(".");
      })
      .test(
        "no-ampersand",
        "Username cannot contain an ampersand",
        function (value) {
          return !value.includes("&");
        }
      )
      .test(
        "no-equals-sign",
        "Username cannot contain an equals sign",
        function (value) {
          return !value.includes("=");
        }
      )
      .test(
        "no-apostrophe",
        "Username cannot contain an apostrophe",
        function (value) {
          return !value.includes("'");
        }
      )
      .test("no-dash", "Username cannot contain a dash", function (value) {
        return !value.includes("-");
      })
      .test(
        "no-plus-sign",
        "Username cannot contain a plus sign",
        function (value) {
          return !value.includes("+");
        }
      )
      .test("no-comma", "Username cannot contain a comma", function (value) {
        return !value.includes(",");
      })
      .test(
        "no-brackets",
        "Username cannot contain brackets",
        function (value) {
          return !value.includes("<") && !value.includes(">");
        }
      )
      .test(
        "no-multiple-periods",
        "Username cannot contain multiple periods in a row",
        function (value) {
          return !value.match(/\.{2,}/);
        }
      )
      .test(
        "no-repeating-characters",
        "Username cannot contain repeating characters",
        function (value) {
          return !value.match(/(.)\1{2,}/);
        }
      )
      .test(
        "only-alphanumeric-characters",
        "Username can only contain letters, numbers, and underscores",
        function (value) {
          return /^[a-zA-Z0-9_]+$/.test(value);
        }
      )
      .required("Username is required"),
  });

  const {
    register,
    handleSubmit,
    formState: { errors, dirtyFields, isDirty, isValid, isSubmitted },
  } = useForm({
    mode: "onChange",
    resolver: yupResolver(schema),
  });

  useEffect(() => {
    if (!usernameAdded) return;
    navigate("/");
  }, [usernameAdded]);

  useEffect(() => {
    if (isValid) {
      setDisplayCheck(true);
      return;
    }
    setDisplayCheck(false);
  }, [isValid]);

  const checkIsAvailable = () => {
    dispatch(checkUsernameIsAvailable({ username: usernameChoice }));
  };

  const onChangeHanlder = (data) => {
    setUsernameChoice(data.username);

    if (error) {
      dispatch(resetError());
    }
    if (usernameIsAvailable) {
      dispatch(resetUsernameIsAvailable());
    }
  };

  const addUsernameToUser = () => {
    dispatch(submitUsername({ username: username }));
  };

  const RenderInputEndAdornment = () => {
    // console.log(isSubmitted);
    if (!displayCheck) return;
    if (usernameIsAvailable) {
      return <HiCheck className=" cursor-default text-green-500 text-xl" />;
    }
    if (error) return;
    if (isLoading) return <Spinner />;
    return <CheckText onClick={checkIsAvailable} />;
  };

  return (
    <div className=" flex justify-center items-center w-full h-full">
      <AuthCard>
        <AuthCardHeading>Create A Username</AuthCardHeading>
        <form
          className="space-y-4"
          onChange={handleSubmit(onChangeHanlder)}
          onSubmit={handleSubmit(addUsernameToUser)}
        >
          <TextInput
            placeholder="Username"
            name="username"
            type="text"
            register={register}
            error={_.isEmpty(errors) ? null : errors.username}
            endAdornment={<RenderInputEndAdornment />}
          />
          <div className="">
            <Button
              primary={true}
              classname={"px-8 py-2 font-semibold text-sm"}
              isButton={true}
              onClick={addUsernameToUser}
              disabled={
                !isDirty ||
                !isValid ||
                !_.isEmpty(error) ||
                isLoading ||
                !usernameIsAvailable
              }
            >
              <div className=" flex gap-1 items-center">
                <p>Update</p>
                <IoIosArrowDroprightCircle className=" inline-block text-white" />
              </div>
            </Button>
          </div>
          {error ? (
            <p className=" text-red-500  uppercase text-xs">{error}</p>
          ) : (
            " "
          )}
        </form>
      </AuthCard>
    </div>
  );
}

export default AddUsername;
