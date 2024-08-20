import React from "react";

function Input(props) {
  const { className, onChange, placeholder, error, ...rest } = props;

  // Determine the border color based on the presence of an error
  const borderColor = error ? "border-red-500" : "border-[#CCCCCC]";

  return (
    <div className="w-1/2 flex flex-col">
      <input
        onChange={onChange}
        placeholder={placeholder}
        className={`w-full h-10 p-2 border rounded undefined bg-[#F3F3F3] text-[#656565] font-medium text-sm leading-[19.6px] ${borderColor} ${className}`}
        {...rest}
      />
      {error && <span className="text-red-500 text-sm">{error}</span>}
    </div>
  );
}

export default Input;
