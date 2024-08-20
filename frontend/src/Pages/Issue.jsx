import React, { useEffect, useState } from "react";
import TextEditor from "../Ui/Form/TextEditor";
import parse from "html-react-parser";
import CommentSection from "../Components/Comments/CommentSection";
import { Avatar, Select } from "antd";
import TextInput from "../Ui/Form/TextInput";
import { IoClose } from "react-icons/io5";
import { FaCheck } from "react-icons/fa6";
import Button from "../Ui/Button";
import { useDispatch, useSelector } from "react-redux";
import _ from "lodash";
import Fishing from "../assets/Fishing.svg";

import {
  getIssue,
  updateFetchedIssueDesc,
  updateFetchedIssueSumm,
} from "../redux/Features/Issue/getIssuesSlice";
import { updateIssue } from "../redux/Features/Issue/updateIssueSlice";
import { deleteIssue } from "../redux/Features/Issue/deleteIssueSlice";
import { enqueueSnackbar } from "notistack";
import { useNavigate, useParams } from "react-router-dom";
import Spinner from "../Ui/Spinner/Spinner";

function Issue() {
  const [isSummaryEditing, setIsSummaryEditing] = useState(false);
  const [isDescriptionEditing, setIsDescriptionEditing] = useState(false);
  const [summary, setSummary] = useState("");
  const [description, setDescription] = useState();
  const [drpStatus, setDrpStatus] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const dispatch = useDispatch();
  const { issueKey } = useParams();
  
  const { issue, status, isfetching } = useSelector((store) => store.getIssue);
  const { isDeleting } = useSelector((store) => store.deleteIssue);
  const { isUpdating } = useSelector((store) => store.updateIssue);

  const navigate = useNavigate();

  useEffect(() => {
    const getIssueByIssueId = async () => {
      const accessToken = localStorage.getItem("accessToken");
      dispatch(getIssue({ accessToken: accessToken, issueKey: issueKey }));
      setIsLoading(false);
    };

    setIsLoading(true);
    getIssueByIssueId();
  }, []);

  useEffect(() => {
    if (isfetching) {
      return;
    }
    if (_.isEmpty(issue) || !status) {
      return;
    }
    setSummary(issue.summary);
    setDescription(issue.description);
    setDrpStatus(issue.status);
  }, [issue]);

  const onClickHeadingUpdate = () => {
    const updatedIssue = {
      summary: summary,
    };

    const accessToken = localStorage.getItem("accessToken");

    dispatch(
      updateIssue({
        accessToken: accessToken,
        issueKey: issueKey,
        updatedIssue: updatedIssue,
      })
    ).then((res) => {
      if (res.payload.data.status) {
        setSummary(res.payload.data.issue.summary);
        enqueueSnackbar(`Updated ${issueKey}`, {
          variant: "success",
          autoHideDuration: 4000,
        });
      }
      toggleSummaryEdit({ updated: true });
    });
  };

  const onClickDescriptionUpdate = () => {
    const updatedIssue = {
      description: description,
    };

    const accessToken = localStorage.getItem("accessToken");

    dispatch(
      updateIssue({
        accessToken: accessToken,
        issueKey: issueKey,
        updatedIssue: updatedIssue,
      })
    ).then((res) => {
      if (res.payload.data.status) {
        console.log(res.payload.data.issue.description);
        setDescription(res.payload.data.issue.description);
        enqueueSnackbar(`Updated ${issueKey}`, {
          variant: "success",
          autoHideDuration: 4000,
        });
      }
      toggleDescriptionEditing({ updated: true });
    });
  };

  const onChangeStatusDropDown = (value) => {
    const updatedIssue = {
      status: value,
    };

    const accessToken = localStorage.getItem("accessToken");

    dispatch(
      updateIssue({
        accessToken: accessToken,
        issueKey: issueKey,
        updatedIssue: updatedIssue,
      })
    ).then((res) => {
      if (res.payload.data.status) {
        setDrpStatus(value);
        enqueueSnackbar(`Updated ${issueKey}`, {
          variant: "success",
          autoHideDuration: 4000,
        });
      }
    });
  };

  const onClickDeleteBtn = () => {
    const accessToken = localStorage.getItem("accessToken");
    dispatch(
      deleteIssue({ accessToken: accessToken, issueKey: issueKey })
    ).then((res) => {
      if (res.payload.data.status) {
        navigate("/");
        enqueueSnackbar(`Deleted ${issueKey}`, {
          variant: "success",
          autoHideDuration: 4000,
        });
      }
    });
  };

  const toggleSummaryEdit = ({ updated }) => {
    setIsSummaryEditing((prevState) => !prevState);

    if (updated) {
      dispatch(updateFetchedIssueSumm(summary));
      return;
    }

    if (issue.summary) {
      setSummary(issue.summary);
    }
  };

  const toggleDescriptionEditing = ({ updated }) => {
    setIsDescriptionEditing((prevState) => !prevState);

    if (updated) {
      dispatch(updateFetchedIssueDesc(description));
      return;
    }
    if (issue.description) {
      setDescription(issue.description);
    }
  };

  const onChangeSummary = (e) => {
    setSummary(e.target.value);
  };

  const onChangeDescription = (e) => {
    setDescription(e);
  };

  return (
    <div className=" w-full flex ">
      {isLoading || isfetching ? (
        <IssueNotFound loading={isLoading || isfetching} />
      ) : (
        <>
          <div className=" w-3/4 space-y-4 h-[95vh] overflow-y-scroll pr-4 ">
            {isSummaryEditing ? (
              <EditableSummary
                value={summary}
                onClickClose={toggleSummaryEdit}
                onClickTick={onClickHeadingUpdate}
                onChange={onChangeSummary}
              />
            ) : (
              <h1
                className=" text-issueHeading text-2xl font-medium hover:bg-gray-100 rounded p-1"
                onClick={toggleSummaryEdit}
              >
                {summary}
              </h1>
            )}

            <div className=" space-y-2 overflow-y-scroll noScrollBar h-[400px] ">
              <Editor
                show={isDescriptionEditing}
                value={description}
                toggleDescriptionEditing={toggleDescriptionEditing}
                onChange={onChangeDescription}
              />
            </div>
            <div>
              <ButtonContainers
                show={isDescriptionEditing}
                cancelAction={toggleDescriptionEditing}
                onClickSave={onClickDescriptionUpdate}
                isEditing={isUpdating}
              />
            </div>
            <div className=" pt-3 ">
              <CommentSection />
            </div>
          </div>
          <div className=" px-3 space-y-4 w-1/4">
            <LeftSide
              deleting={isDeleting}
              value={drpStatus}
              onChange={onChangeStatusDropDown}
              onClickDelete={onClickDeleteBtn}
            />
          </div>
        </>
      )}
    </div>
  );
}

export default Issue;

const EditableSummary = ({ value, onClickClose, onClickTick, onChange }) => {
  return (
    <div>
      <TextInput value={value} onChange={onChange} />
      <div className="w-full flex items-center justify-end space-x-2 pt-2">
        <div
          className=" cursor-pointer p-2 custom-shadow rounded bg-white hover:bg-gray-200"
          onClick={onClickTick}
        >
          <FaCheck />
        </div>

        <div
          className=" cursor-pointer p-2 custom-shadow rounded bg-white hover:bg-gray-200"
          onClick={onClickClose}
        >
          <IoClose />
        </div>
      </div>
    </div>
  );
};

const LeftSide = (props) => {
  const { value, onChange, onClickDelete, deleting } = props;

  return (
    <>
      <div>
        {value && (
          <Select
            defaultValue={value.toUpperCase()}
            style={{ width: "100%" }}
            onChange={onChange}
            options={[
              { value: "OPEN", label: "OPEN" },
              { value: "IN PROGRESS", label: "IN PROGRESS" },
              { value: "REVIEW", label: "REVIEW" },
              { value: "DONE", label: "DONE" },
            ]}
          />
        )}
      </div>
      <div className=" space-y-2 border border-[#DFE1E6] w-full rounded px-4 py-2">
        <div>
          <span className="text-issueHeading text-sm font-medium">
            Reporter
          </span>
        </div>
        <div className=" flex items-center gap-2">
          <Avatar size="small" src={"https://joesch.moe/api/v1/random"} />
          <span className="">John Doe</span>
        </div>
      </div>
      <Button
        isButton
        className=" bg-red-600 w-full"
        onClick={onClickDelete}
        disabled={deleting}
      >
        {deleting ? (
          <Spinner className=" h-3 w-3 disabled:cursor-wait" />
        ) : (
          "Delete"
        )}
      </Button>
    </>
  );
};

const Editor = (props) => {
  const { show, value, toggleDescriptionEditing, onChange } = props;
  return (
    <>
      <label className=" text-issueHeading text-sm font-normal">
        Description
      </label>
      <div className=" mb-5 ">
        <div
          className="result hover:bg-gray-100 rounded p-1"
          onClick={toggleDescriptionEditing}
        >
          {!show && value && parse(value)}
        </div>
        <div className="editor-container block">
          {show && (
            <TextEditor
              value={value}
              onChange={onChange}
              className="w-full !rounded h-[350px]"
            />
          )}
        </div>
      </div>
    </>
  );
};

const ButtonContainers = (props) => {
  const { show, cancelAction, onClickSave, isEditing } = props;
  return (
    <div className="">
      {show && (
        <div className=" flex items-center gap-2">
          <Button isButton={true} disabled={isEditing} onClick={onClickSave}>
            {isEditing ? <Spinner className="mx-3" /> : "Save"}
          </Button>
          <Button
            isButton={true}
            onClick={cancelAction}
            className="bg-transparent !text-buttonPrimary hover:bg-slate-100"
          >
            Cancel
          </Button>
        </div>
      )}
    </div>
  );
};

const IssueNotFound = ({ loading }) => {
  return (
    <div className="w-full flex flex-col items-center justify-center mt-5 gap-6">
      {loading ? (
        <Spinner className="w-[20%] h-[20%]" />
      ) : (
        <>
          <img
            src={Fishing}
            alt="Issue not found SVG"
            className=" h-auto w-[40%]"
          />
          <h1 className=" text-buttonPrimary font-normal text-lg">
            Issue not found or you dont have access to it.
          </h1>
        </>
      )}
    </div>
  );
};
