import React from "react";
import { Link } from "react-router-dom";
import _ from "lodash";

function IssueItem(props) {
  const { summary, issueKey, status, assignee } = props;
  return (
    <div className="flex items-center py-3 px-4 text-sm text-[#172B4D] font-medium hover:bg-slate-100">
      <div className="w-1/4">
        <Link to={`/issue/${issueKey}`}>{issueKey}</Link>
      </div>
      <div className="w-full">
        <Link to={`/issue/${issueKey}`}>{summary}</Link>
      </div>
      <div className="w-1/4">John Doe</div>
      <div className="w-1/4">{_.capitalize(status)}</div>
    </div>
  );
}

export default IssueItem;
