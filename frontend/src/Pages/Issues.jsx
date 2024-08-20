import React, { useEffect } from "react";
import IssueItem from "../Components/IssueItem";
import { useDispatch, useSelector } from "react-redux";
import { getAllIssues } from "../redux/Features/Issue/getIssuesSlice";

function Issues() {
  const dispatch = useDispatch();

  const { issues } = useSelector((store) => store.getIssue);

  useEffect(() => {
    const getIssues = async () => {
      const accessToken = localStorage.getItem("accessToken");
      await dispatch(getAllIssues(accessToken));
    };

    getIssues();
  }, []);

  return (
    <div className=" w-full ">
      <div className="flex flex-col absolute w-[75%]">
        <div className="flex items-center py-2 px-4 font-medium text-sm border-b-2 border-b-gray-200 relative top-0 text-[#172B4D]">
          <div className="w-1/4">Key</div>
          <div className="w-full">Summary</div>
          <div className="w-1/4">Assignee</div>
          <div className="w-1/4 ">Status</div>
        </div>
        <div className="flex flex-col space-y-2 ">
          {console.log(issues)}
          {issues &&
            issues?.length > 0 &&
            issues.map((issue) => (
              <IssueItem
                summary={issue.summary}
                issueKey={issue.issueKey}
                status={issue.status}
              />
            ))}
        </div>
      </div>
    </div>
  );
}

export default Issues;
