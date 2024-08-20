import { Avatar } from "antd";
import React from "react";
import parse from "html-react-parser";
import Timestamp from "react-timestamp";

function Comments({ username, text, timeStamp }) {
  return (
    <div className=" w-full flex items-center">
      <div className=" w-full flex items-start gap-3">
        <Avatar size="large" src={`https://joesch.moe/api/v1/${timeStamp}`} />
        <div className=" ">
          <div className=" flex items-center gap-4">
            <p className=" text-sm text-[#42526E]">{username}</p>
            <span className=" text-sm font-light text-[#626F86]">
              <Timestamp relative date={timeStamp} autoUpdate />
            </span>
          </div>
          <div className="result text-xs">{parse(text)}</div>
        </div>
      </div>
    </div>
  );
}

export default Comments;
