import React, { useState } from "react";

import ProfilePicture from "../assets/ProfilePicture.png";
import { useNavigate } from "react-router-dom";
import Button from "../Ui/Button";
import { setIsModalOpen } from "../redux/Features/Modal/modalSlice";
import { useDispatch, useSelector } from "react-redux";
import { logoutUser } from "../redux/Features/Auth/authSlice";

function Navbar() {
  const navigate = useNavigate();
  const dispatch = useDispatch();

  const [isDropdownVisible, setIsDropdownVisible] = useState(false);
  const isAuthenticated = true;
  const jiraUsername = "Sarandeep";
  const userEmail = "sarandeepachu@gmail.com";

  const { user, isGettingUserOrToken } = useSelector((store) => store.auth);

  const toggleDropdown = () => {
    setIsDropdownVisible(!isDropdownVisible);
  };

  const onClickSignOut = () => {
    dispatch(logoutUser());
    navigate("/auth");
  };

  const onClickCreate = () => {
    dispatch(setIsModalOpen({ isOpen: true }));
  };

  return (
    <>
      <nav className="flex fixed top-0 left-0 z-50 justify-between items-center bg-white h-[60px] pl-14  pr-5 w-full shadow-sm border border-gray-100 ">
        <div className=" flex justify-between items-center gap-12">
          <a href="/">
            {/* <img src={refLogo} alt="Reflections Logo" className="h-8" />
             */}
            <h1 className=" text-[#0c66e4] font-bold text-3xl">Bug Hunter</h1>
          </a>
          <div>
            {user?.isLoggedIn && user.username && (
              <Button isButton={true} onClick={onClickCreate}>
                Create
              </Button>
            )}
          </div>
        </div>

        {user?.isLoggedIn && user.username && (
          <div
            className="relative cursor-pointer inline-flex borde  borde p-1"
            onMouseEnter={() => setIsDropdownVisible(true)}
            onMouseLeave={() => setIsDropdownVisible(false)}
          >
            <button
              type="button"
              className=" rounded-full ml-auto"
              onClick={toggleDropdown}
            >
              <img
                className="w-10 h-10 rounded-full "
                src={ProfilePicture}
                alt="user photo"
              />
            </button>

            <div
              className={`absolute z-50 min-w-[150px] right-0 top-11 border border-gray-100 bg-white divide-gray-100 cursor-pointer rounded-lg shadow-2xl ${
                isDropdownVisible ? "block" : "hidden"
              }`}
              onMouseEnter={() => setIsDropdownVisible(true)}
              onMouseLeave={() => setIsDropdownVisible(false)}
            >
              <ul className="py-2 text-left">
                <li className=" px-2 cursor-default">
                  <div className="px-2 py-2">
                    <p className=" text-buttonPrimary font-medium">
                      {user?.username}
                    </p>
                  </div>
                </li>
                <li
                  className="block px-4 py-2 text-sm font-light text-black hover:bg-gray-300 hover:text-gray-700"
                  onClick={onClickSignOut}
                >
                  Sign out
                </li>
              </ul>
            </div>
          </div>
        )}
      </nav>
      <div className="h-[60px]"></div>
    </>
  );
}

export default Navbar;
