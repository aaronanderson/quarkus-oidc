import React from "react";

import { Router, RouteComponentProps } from "@reach/router";

import {HomePage} from './pages/HomePage'


//https://github.com/reach/router/issues/141#issuecomment-519391553
interface ExtendProps extends React.PropsWithChildren<any> {
	pageComponent: React.ComponentType 
}

const RouterPage = ({children, ...props}: ExtendProps & RouteComponentProps): React.ReactElement => {
	const {pageComponent, ...others} = props;
	return (
		<props.pageComponent {...others}>
			{children}
		</props.pageComponent>
	)
};

export default RouterPage;




export class OIDC extends React.Component {

	render() {
     return( 

        <Router>
            <RouterPage path="/" pageComponent={HomePage}/>           
        </Router>


     );
	} 
}


