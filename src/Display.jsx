import React from "react";
import ReactMarkdown from "react-markdown";
import rehypeHighlight from "rehype-highlight";
import "github-markdown-css";
import './Display.css'

const MyComponent = () => {
  const markdown = `
# This is a heading

This is some **bold** text.

\`\`\`javascript
console.log('Hello, world!');
\`\`\`

* Item 1
* Item 2

`;

  return (
    <div className="">
    <div style={{boxShadow:"0px 4px #888888",border:"1px solid black",backgroundColor:"#D9D9D9"}} className="drop-shadow-md border w-210 rounded-lg pl-2 pt-5 flex flex-col ">
    <div className="markdown-body w-200 h-40 overflow-auto ">
      <ReactMarkdown rehypePlugins={[rehypeHighlight]} children={markdown} />
    </div>
    <h2 className="text-[40px]">title</h2>
    <p className=" pb-2">Description</p>
    </div>
    </div>
  );
};

export default MyComponent;
