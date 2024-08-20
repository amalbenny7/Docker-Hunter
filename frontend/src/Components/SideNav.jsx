import React from "react";
import { NavLink } from "react-router-dom";
import ProjectIcon from "../assets/Project Icon.svg";

function SideNav(props) {
  const { items, selectedItem } = props;



  const commonClasses =
    "py-[10px] pl-[17px] pr-[7px] text-sm  leading-3 text-buttonPrimary focus:outline-none bg-white rounded  hover:bg-buttonBg  duration-100";

  return (
    <div className="w-1/5 bg-white p-4   border-r-2 space-y-6">
      <div className=" flex items-center gap-2">
        <span className=" h-9 w-9">
          <img src={ProjectIcon} alt="Project Icon" className="w-full h-full" />
        </span>
        <div className=" flex flex-col ">
          <h3 className="text-base">Projet Name</h3>
          <p className=" text-xs font-light text-primary">Software Project</p>
        </div>
      </div>
      <div className="">
        <h4 className="uppercase text-xs font-bold text-secondary tracking-wide">
          Planning
        </h4>
      </div>
      <ul className="">
        {items.map((item) => (
          <li key={item.name}>
            <NavLink
              to={item.to}
              className={({ isActive }) =>
                isActive
                  ? `${commonClasses} flex items-center gap-2 !bg-buttonBg !text-blueish `
                  : `${commonClasses} flex items-center gap-2`
              }
            >
              <span>{item.icon}</span>
              <span>{item.name}</span>
            </NavLink>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default SideNav;
