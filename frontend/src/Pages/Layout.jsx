import React, { useEffect, useState } from "react";
import SideNav from "../Components/SideNav";
import { GrScorecard } from "react-icons/gr";
import { BiSolidDashboard } from "react-icons/bi";
import Navbar from "../Components/Navbar";
import Footer from "../Components/Footer";
import { Outlet } from "react-router-dom";
import { SnackbarProvider, enqueueSnackbar } from "notistack";
import CreateIssue from "../Components/CreateIssue/CreateIssue";
import { setIsModalOpen } from "../redux/Features/Modal/modalSlice";
import { useDispatch, useSelector } from "react-redux";
import _ from "lodash";
import Modal from "../Components/Modal/Modal";
import {
  createIssue,
  resetState,
} from "../redux/Features/Issue/createIssueSlice";

function Layout() {
  const items = [
    { name: "Board", to: "/", icon: <BiSolidDashboard /> },
    { name: "Issues", to: "issues", icon: <GrScorecard /> },
  ];

  const [formValues, setFormValues] = useState({
    description: "",
    summary: "",
  });
  const [formError, setFormError] = useState({});

  const dispatch = useDispatch();

  // const { isCreating, issue, status, error } = useSelector(
  //   (store) => store.create
  // );

  const resetLocalState = () => {
    setFormValues({ ...formValues, summary: "", description: "" });
  };

  const { isCreating, status, error, issue } = useSelector(
    (store) => store.createIssue
  );

  const { user } = useSelector((store) => store.auth);

  useEffect(() => {
    if (!_.isEmpty(issue) && status) {
      dispatch(setIsModalOpen({ isOpen: false }));
      setFormValues({ ...formValues, summary: "", description: "" });
      enqueueSnackbar(`Successfully created ${issue.issueKey} `, {
        variant: "success",
        autoHideDuration: 4000,
      });
      dispatch(resetState());
    }
  }, [issue]);

  const onChangeInEditor = (content) => {
    setFormValues({
      ...formValues,
      description: content,
    });
  };

  const onChangeSummary = (e) => {
    e.preventDefault();
    setFormValues({ ...formValues, summary: e.target.value });
    setFormError({
      ...formError,
      summary:
        e.target.value.trim() === ""
          ? { message: "Summary is required" }
          : null,
    });
  };

  const onClickSubmit = async () => {
    if (formValues.summary.trim() === "") {
      setFormError({
        ...formError,
        summary: { message: "Summary is required" },
      });
      return;
    }

    const accessToken = localStorage.getItem("accessToken");

    const formData = { ...formValues, userId: user.userId };

    dispatch(createIssue({ accessToken: accessToken, issueDetails: formData }));
  };

  return (
    <div className="min-h-screen h-screen">
      <Navbar />
      <SnackbarProvider maxSnack={3} />
      <div className="flex-grow h-[90%]">
        <div className="flex flex-row h-full">
          <SideNav items={items} />
          <div className="w-4/5 bg-white p-4 overflow-clip">
            <Outlet />
          </div>
        </div>
      </div>

      <Modal
        className="w-[780px] h-[535px]"
        onClickFooterButton={onClickSubmit}
        loading={isCreating}
        onModalClose={resetLocalState}
      >
        <CreateIssue
          onChangeInEditor={onChangeInEditor}
          onChangeSummary={onChangeSummary}
          error={formError}
          formValues={formValues}
        />
      </Modal>
      {/* <Footer /> */}
    </div>
  );
}

export default Layout;
