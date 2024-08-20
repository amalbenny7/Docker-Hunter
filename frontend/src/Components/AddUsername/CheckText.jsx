import React from "react";

function CheckText(props) {
  const { onClick, className } = props;
  return (
    <p
      type="submit"
      className={` text-my-ebonyClay-400 text-xs font-semibold hover:text-placeholder-ash transition duration-100 ${
        className ? className : " "
      }`}
      onClick={() => onClick()}
    >
      Check
    </p>
  );
}

export default CheckText;
